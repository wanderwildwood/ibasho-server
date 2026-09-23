import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { desktopEntry, install, useInstall } from '@/lib/install';
import { useStore, type Theme } from '@/lib/store';

// Auto, then light, then dark, as on kotozute's Desktop Sync page: one small pill that says
// what it is set to, rather than a menu.
const NEXT: Record<Theme, Theme> = { system: 'light', light: 'dark', dark: 'system' };

export const ThemeCycleButton = () => {
  const { t } = useTranslation('common');
  const { theme, setTheme } = useStore();
  const label = {
    system: t('desktop.theme_auto'),
    light: t('desktop.theme_light'),
    dark: t('desktop.theme_dark'),
  }[theme];

  return (
    <Button
      variant="outline"
      size="sm"
      title={t('desktop.theme_title')}
      onClick={() => setTheme(NEXT[theme])}
    >
      {label}
    </Button>
  );
};

const agent = navigator.userAgent;
const platform =
  (navigator as Navigator & { userAgentData?: { platform?: string } }).userAgentData?.platform ||
  navigator.platform ||
  '';
const isAndroid = /android/i.test(agent);
const isLinux = /linux/i.test(platform) && !isAndroid;
const isMac = /mac/i.test(platform);
const isChromium = 'chrome' in window || /Chrome|Chromium|Edg|Brave|Vivaldi|OPR/.test(agent);

const LauncherHelp = () => {
  const { t } = useTranslation('common');
  const url = window.location.origin + window.location.pathname;

  const download = () => {
    const blob = new Blob([desktopEntry(url)], { type: 'application/x-desktop' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'whereabouts.desktop';
    a.click();
    URL.revokeObjectURL(a.href);
  };

  if (isLinux) {
    return (
      <div className="space-y-3 text-sm">
        <p>{t('desktop.linux_text')}</p>
        <Button onClick={download}>{t('desktop.linux_download')}</Button>
        <p>
          {t('desktop.linux_where')} <code>~/.local/share/applications/</code>
        </p>
      </div>
    );
  }
  if (isChromium) {
    return <p className="text-sm">{t('desktop.chromium_text')}</p>;
  }
  if (isMac) {
    return <p className="text-sm">{t('desktop.safari_text')}</p>;
  }
  return <p className="text-sm">{t('desktop.other_text')}</p>;
};

export const InstallControls = () => {
  const { t } = useTranslation('common');
  const { prompt, installed } = useInstall();
  const [helpOpen, setHelpOpen] = useState(false);

  // Inside the installed window there is nothing left to offer.
  if (installed) return null;

  return (
    <>
      {prompt ? (
        <Button
          variant="outline"
          size="sm"
          onClick={() => void install()}
          title={t('desktop.install_title')}
        >
          {t('desktop.install')}
        </Button>
      ) : (
        <Button
          variant="outline"
          size="sm"
          onClick={() => setHelpOpen(true)}
          title={t('desktop.install_title')}
        >
          {t('desktop.launcher')}
        </Button>
      )}

      <Dialog open={helpOpen} onOpenChange={setHelpOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('desktop.launcher_title')}</DialogTitle>
            <DialogDescription>{t('desktop.launcher_description')}</DialogDescription>
          </DialogHeader>
          <LauncherHelp />
        </DialogContent>
      </Dialog>
    </>
  );
};
