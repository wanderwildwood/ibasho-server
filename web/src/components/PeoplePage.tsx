import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import type * as LeafletType from 'leaflet';
import { toast } from 'sonner';
import { ArrowLeft, MapPin, RefreshCw } from 'lucide-react';
import { LoginForm } from '@/components/LoginForm';
import { Header } from '@/components/Header';
import { BatteryIndicator } from '@/components/BatteryIndicator';
import { Button } from '@/components/ui/button';
import { Spinner } from '@/components/ui/spinner';
import { apiService } from '@/lib/apiService';
import { loadPeople, NeedsLogin, setPaused, type People, type Person } from '@/lib/people';
import { useStore } from '@/lib/store';
import { useThemeColors } from '@/hooks/useThemeColors';

import 'leaflet/dist/leaflet.css';

const minute = 60 * 1000;
const hour = 60 * minute;

// Phones report on their own schedule; a look every minute while the page is in view is plenty.
const POLL_INTERVAL = minute;

const MARKER_RADIUS = 8;

// Names come from other people's accounts and go into Leaflet's HTML, so they are escaped.
const escapeHtml = (s: string) =>
  s.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!
  );

const formatAge = (when: number, t: TFunction<'dashboard'>) => {
  const age = Date.now() - when;
  if (age < minute) return t('family.just_now');
  if (age < hour) return t('family.minutes_ago', { count: Math.floor(age / minute) });
  if (age < 24 * hour) return t('family.hours_ago', { count: Math.floor(age / hour) });
  return new Date(when).toLocaleString();
};

const PersonRow = ({ person, onShow }: { person: Person; onShow: (p: Person) => void }) => {
  const { t } = useTranslation('dashboard');
  const loc = person.location;

  const line = (() => {
    switch (person.state) {
      case 'ok':
        return formatAge(loc!.date ?? person.unixMillis!, t);
      case 'paused':
        return t('people.paused');
      case 'no_key':
        return t('people.not_set_up');
      case 'unreadable':
        return t('people.unreadable');
      default:
        return t('people.none');
    }
  })();

  return (
    <li className="dark:border-fmd-dark-border border-t border-gray-200 first:border-t-0">
      <button
        type="button"
        className="flex w-full min-w-0 items-center gap-3 py-3 text-left disabled:cursor-default"
        disabled={!loc}
        onClick={() => onShow(person)}
        title={loc ? t('family.show_on_map') : undefined}
      >
        <MapPin
          className={`h-4 w-4 shrink-0 ${loc ? 'text-fmd-green' : 'text-gray-400 dark:text-gray-600'}`}
        />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-medium text-gray-900 dark:text-white">
            {person.name}
          </span>
          <span className="block text-xs text-gray-500 dark:text-gray-400">{line}</span>
        </span>
        {loc && Number.isFinite(Number(loc.bat)) && (
          <BatteryIndicator percentage={Number(loc.bat)} />
        )}
      </button>
    </li>
  );
};

const PeoplePage = () => {
  const { t } = useTranslation('dashboard');
  const { isLoggedIn, userData, wasAuthRestoreTried } = useStore();
  const { mapAccentColor } = useThemeColors();

  const [data, setData] = useState<People | null>(null);
  const [loading, setLoading] = useState(false);
  const [needsLogin, setNeedsLogin] = useState(false);
  const [error, setError] = useState('');
  const [tileUrl, setTileUrl] = useState('');

  const mapDiv = useRef<HTMLDivElement>(null);
  const map = useRef<LeafletType.Map | null>(null);
  const leaflet = useRef<typeof LeafletType | null>(null);
  const layer = useRef<LeafletType.LayerGroup | null>(null);
  const markers = useRef<Map<string, LeafletType.CircleMarker>>(new Map());
  const fitted = useRef(false);
  const [mapReady, setMapReady] = useState(false);

  const refresh = useCallback(async (showSpinner = true) => {
    if (showSpinner) setLoading(true);
    try {
      setData(await loadPeople());
      setError('');
      setNeedsLogin(false);
    } catch (e) {
      if (e instanceof NeedsLogin) setNeedsLogin(true);
      else setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (showSpinner) setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isLoggedIn && userData) void refresh();
  }, [isLoggedIn, userData, refresh]);

  useEffect(() => {
    if (!isLoggedIn || !userData) return;
    const id = setInterval(() => {
      if (!document.hidden) void refresh(false);
    }, POLL_INTERVAL);
    return () => clearInterval(id);
  }, [isLoggedIn, userData, refresh]);

  useEffect(() => {
    void (async () => {
      try {
        setTileUrl(await apiService().getTileServerUrl());
      } catch {
        setTileUrl('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png');
      }
    })();
  }, []);

  // The map itself.
  useEffect(() => {
    if (!mapDiv.current || map.current || !tileUrl || !isLoggedIn) return;
    let cancelled = false;
    void (async () => {
      const L = (await import('leaflet')).default;
      if (cancelled || !mapDiv.current || map.current) return;
      leaflet.current = L;
      const m = L.map(mapDiv.current).setView([20, 0], 2);
      L.tileLayer(tileUrl, {
        attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
        maxZoom: 19,
      }).addTo(m);
      m.attributionControl.setPrefix('');
      layer.current = L.layerGroup().addTo(m);
      map.current = m;
      setMapReady(true);
    })();
    return () => {
      cancelled = true;
      map.current?.remove();
      map.current = null;
      setMapReady(false);
    };
  }, [tileUrl, isLoggedIn, wasAuthRestoreTried]);

  // One named dot per person, at the last place they shared. No trail.
  useEffect(() => {
    const L = leaflet.current;
    const m = map.current;
    if (!L || !m || !layer.current || !data) return;
    layer.current.clearLayers();
    markers.current.clear();

    const points: [number, number][] = [];
    for (const p of data.people) {
      const loc = p.location;
      if (!loc) continue;
      const accuracy = Number(loc.accuracy);
      if (accuracy > 0) {
        L.circle([loc.lat, loc.lon], {
          radius: accuracy,
          color: mapAccentColor,
          fillColor: mapAccentColor,
          fillOpacity: 0.25,
          weight: 0,
        }).addTo(layer.current);
      }
      const marker = L.circleMarker([loc.lat, loc.lon], {
        radius: MARKER_RADIUS,
        color: '#ffffff',
        weight: 2,
        fillColor: mapAccentColor,
        fillOpacity: 1,
      })
        .addTo(layer.current)
        .bindTooltip(escapeHtml(p.name), { permanent: true, direction: 'right', offset: [8, 0] })
        .bindPopup(
          `<strong>${escapeHtml(p.name)}</strong><br/>${escapeHtml(
            new Date(Number(loc.date)).toLocaleString()
          )}`
        );
      markers.current.set(p.name, marker);
      points.push([loc.lat, loc.lon]);
    }
    if (!fitted.current && points.length > 0) {
      fitted.current = true;
      m.fitBounds(points, { maxZoom: 15, padding: [40, 40] });
    }
  }, [data, mapAccentColor, mapReady]);

  const show = (p: Person) => {
    const marker = markers.current.get(p.name);
    if (!marker || !map.current) return;
    map.current.setView(marker.getLatLng(), Math.max(map.current.getZoom(), 15));
    marker.openPopup();
  };

  const togglePause = async () => {
    if (!data) return;
    const next = !data.paused;
    try {
      await setPaused(next);
      await refresh(false);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t('people.failed'));
    }
  };

  if (!wasAuthRestoreTried) {
    return (
      <div className="dark:bg-fmd-dark-lighter flex min-h-screen items-center justify-center bg-gray-50">
        <Spinner size="lg" />
      </div>
    );
  }

  if (!isLoggedIn) {
    return (
      <div className="dark:bg-fmd-dark-lighter flex min-h-screen items-center justify-center bg-gray-50">
        <LoginForm />
      </div>
    );
  }

  return (
    <>
      <Header onSettingsClick={() => {}} onAccountInfoClick={() => {}} />
      <div className="dark:bg-fmd-dark-lighter flex h-[calc(100vh-3.1rem)] flex-col bg-gray-50 text-gray-900 dark:text-white">
        <div className="flex flex-1 flex-col gap-4 overflow-y-auto p-4 lg:flex-row lg:overflow-hidden">
          <div className="order-2 flex w-full flex-col gap-4 lg:order-1 lg:min-h-0 lg:w-100 lg:shrink-0">
            <div className="dark:bg-fmd-dark rounded-lg bg-white p-4 shadow-sm lg:min-h-0 lg:overflow-y-auto">
              <div className="mb-2 flex items-center justify-between gap-2">
                <Link
                  to="/"
                  className="flex items-center gap-1 text-sm text-gray-500 hover:underline dark:text-gray-400"
                >
                  <ArrowLeft className="h-4 w-4" />
                  {t('people.back')}
                </Link>
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label={t('people.refresh')}
                  title={t('people.refresh')}
                  onClick={() => void refresh()}
                >
                  {loading ? <Spinner size="sm" /> : <RefreshCw className="h-4 w-4" />}
                </Button>
              </div>
              <h2 className="mb-2 text-base font-semibold">{t('people.title')}</h2>

              {needsLogin && <p className="text-sm">{t('people.log_in_again')}</p>}
              {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

              {data && (
                <>
                  {data.people.length === 0 ? (
                    <p className="text-sm text-gray-500 dark:text-gray-400">{t('people.empty')}</p>
                  ) : (
                    <ul>
                      {data.people.map((p) => (
                        <PersonRow key={p.name} person={p} onShow={show} />
                      ))}
                    </ul>
                  )}

                  <label className="dark:border-fmd-dark-border mt-3 flex cursor-pointer items-center gap-3 border-t border-gray-200 pt-3 text-sm">
                    <input
                      type="checkbox"
                      className="h-4 w-4"
                      checked={data.paused}
                      onChange={() => void togglePause()}
                    />
                    <span>
                      {t('people.pause')}
                      <span className="block text-xs text-gray-500 dark:text-gray-400">
                        {data.paused ? t('people.pause_on') : t('people.pause_off')}
                      </span>
                    </span>
                  </label>
                </>
              )}
            </div>
          </div>

          <div className="order-1 min-h-96 flex-1 rounded-lg lg:order-2 lg:min-h-0">
            <div className="bg-fmd-light dark:bg-fmd-dark relative h-full w-full rounded-lg">
              <div ref={mapDiv} className="h-full min-h-96 w-full rounded-lg" />
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default PeoplePage;
