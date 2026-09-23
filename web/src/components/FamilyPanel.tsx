import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { toast } from 'sonner';
import { MapPin, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { BatteryIndicator } from '@/components/BatteryIndicator';
import { PasswordInput } from '@/components/PasswordInput';
import { ConfirmModal } from '@/components/modals/ConfirmModal';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Spinner } from '@/components/ui/spinner';
import {
  addDevice,
  focusDevice,
  reenterPassword,
  refreshAll,
  removeDevice,
  useFamily,
  type FamilyDevice,
} from '@/lib/family';

const minute = 60 * 1000;
const hour = 60 * minute;

// Other people's phones report on their own schedule; checking every few minutes while the
// page is in view is plenty, and nothing is fetched while the tab is hidden.
const POLL_INTERVAL = 5 * minute;

// "4 min ago" for today's fixes, the date and time for anything older than a day.
const formatAge = (date: number, t: TFunction<'dashboard'>) => {
  const age = Date.now() - date;
  if (age < minute) return t('family.just_now');
  if (age < hour) return t('family.minutes_ago', { count: Math.floor(age / minute) });
  if (age < 24 * hour) return t('family.hours_ago', { count: Math.floor(age / hour) });
  return new Date(date).toLocaleString();
};

const DeviceRow = ({ device }: { device: FamilyDevice }) => {
  const { t } = useTranslation('dashboard');
  const status = useFamily((s) => s.status[device.fmdId]);
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);

  const location = status?.location;

  const submitPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await reenterPassword(device.fmdId, password);
      setPassword('');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('family.add_failed'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <li className="dark:border-fmd-dark-border border-t border-gray-200 py-3 first:border-t-0">
      <div className="flex items-center gap-3">
        <button
          type="button"
          className="flex min-w-0 flex-1 items-center gap-2 text-left disabled:cursor-default"
          disabled={!location}
          onClick={() => focusDevice(device.fmdId)}
          title={location ? t('family.show_on_map') : undefined}
        >
          <MapPin className="text-fmd-green h-4 w-4 shrink-0" />
          <span className="min-w-0">
            <span className="block truncate text-sm font-medium text-gray-900 dark:text-white">
              {device.name}
            </span>
            <span className="block text-xs text-gray-500 dark:text-gray-400">
              {status?.loading && !location
                ? t('loading')
                : location
                  ? formatAge(location.date, t)
                  : status?.error
                    ? status.error
                    : t('family.no_location')}
            </span>
          </span>
        </button>

        {location && <BatteryIndicator percentage={location.bat} />}

        <Button
          variant="ghost"
          size="icon"
          aria-label={t('family.remove')}
          title={t('family.remove')}
          onClick={() => setConfirmRemove(true)}
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      </div>

      {status?.needsPassword && (
        <form onSubmit={(e) => void submitPassword(e)} className="mt-2 flex gap-2">
          <PasswordInput
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={t('family.new_password')}
            required
          />
          <Button type="submit" disabled={busy || !password}>
            {busy ? <Spinner size="sm" /> : t('family.log_in')}
          </Button>
        </form>
      )}

      <ConfirmModal
        isOpen={confirmRemove}
        title={t('family.remove_title', { name: device.name })}
        message={t('family.remove_message')}
        confirmText={t('family.remove')}
        variant="destructive"
        onCancel={() => setConfirmRemove(false)}
        onConfirm={() => {
          setConfirmRemove(false);
          void removeDevice(device.fmdId);
        }}
      />
    </li>
  );
};

const AddDeviceForm = ({ onDone }: { onDone: () => void }) => {
  const { t } = useTranslation('dashboard');
  const [name, setName] = useState('');
  const [fmdId, setFmdId] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await addDevice(fmdId, password, name);
      onDone();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t('family.add_failed'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={(e) => void submit(e)} className="mt-3 flex flex-col gap-2">
      <Input
        value={name}
        onChange={(e) => setName(e.target.value)}
        placeholder={t('family.name')}
        autoComplete="off"
      />
      <Input
        value={fmdId}
        onChange={(e) => setFmdId(e.target.value)}
        placeholder={t('family.fmd_id')}
        autoComplete="off"
        autoCapitalize="none"
        required
      />
      <PasswordInput
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder={t('family.password')}
        autoComplete="off"
        required
      />
      <p className="text-xs text-gray-500 dark:text-gray-400">{t('family.add_hint')}</p>
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onDone} disabled={busy}>
          {t('family.cancel')}
        </Button>
        <Button type="submit" disabled={busy || !fmdId || !password}>
          {busy ? <Spinner size="sm" /> : t('family.add')}
        </Button>
      </div>
    </form>
  );
};

export const FamilyPanel = () => {
  const { t } = useTranslation('dashboard');
  const devices = useFamily((s) => s.devices);
  const anyLoading = useFamily((s) => Object.values(s.status).some((d) => d.loading));
  const [adding, setAdding] = useState(false);

  useEffect(() => {
    void refreshAll();
    const id = setInterval(() => {
      if (!document.hidden) void refreshAll();
    }, POLL_INTERVAL);
    const onVisible = () => {
      if (!document.hidden) void refreshAll();
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      clearInterval(id);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, []);

  return (
    <div className="dark:border-fmd-dark-border dark:bg-fmd-dark shrink-0 rounded-lg border border-gray-200 bg-white p-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-gray-900 dark:text-white">{t('family.title')}</h2>
        <div className="flex gap-1">
          {devices.length > 0 && (
            <Button
              variant="ghost"
              size="icon"
              aria-label={t('family.refresh')}
              title={t('family.refresh')}
              disabled={anyLoading}
              onClick={() => void refreshAll()}
            >
              <RefreshCw className={anyLoading ? 'h-4 w-4 animate-spin' : 'h-4 w-4'} />
            </Button>
          )}
          {!adding && (
            <Button
              variant="ghost"
              size="icon"
              aria-label={t('family.add_device')}
              title={t('family.add_device')}
              onClick={() => setAdding(true)}
            >
              <Plus className="h-4 w-4" />
            </Button>
          )}
        </div>
      </div>

      {devices.length === 0 && !adding && (
        <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">{t('family.empty')}</p>
      )}

      {devices.length > 0 && (
        <ul className="mt-1">
          {devices.map((d) => (
            <DeviceRow key={d.fmdId} device={d} />
          ))}
        </ul>
      )}

      {adding && <AddDeviceForm onDone={() => setAdding(false)} />}
    </div>
  );
};
