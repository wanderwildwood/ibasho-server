import { create } from 'zustand';

// Chromium offers to install the page as an app by firing beforeinstallprompt once, early,
// often before the dashboard's code has even loaded. So it is caught here, at startup, and
// kept until someone presses Install. Firefox and Safari never fire it; they install
// through their own menus, which the launcher help describes instead.

interface InstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed' }>;
}

interface InstallState {
  prompt: InstallPromptEvent | null;
  installed: boolean;
}

export const useInstall = create<InstallState>()(() => ({
  prompt: null,
  installed: window.matchMedia('(display-mode: standalone)').matches,
}));

window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  useInstall.setState({ prompt: e as InstallPromptEvent });
});

window.addEventListener('appinstalled', () => {
  useInstall.setState({ prompt: null, installed: true });
});

export async function install(): Promise<void> {
  const { prompt } = useInstall.getState();
  if (!prompt) return;
  await prompt.prompt();
  await prompt.userChoice;
  useInstall.setState({ prompt: null });
}

// A Linux launcher, as kotozute's Desktop Sync makes one: it opens this page as a window of
// its own in a Chromium browser where there is one, installed normally or as a Flatpak, and
// in the usual browser where not.
export function desktopEntry(url: string): string {
  // The desktop-entry spec wants the script as one double-quoted argument. Inside it a $
  // must be escaped as \$, and the file format doubles that backslash again, so the file
  // holds \\$ (written '\\\\$' in this source). desktop-file-validate accepts the result.
  const script =
    'for b in brave-browser brave chromium chromium-browser google-chrome ' +
    'google-chrome-stable microsoft-edge vivaldi; do command -v \\\\$b >/dev/null 2>&1 && ' +
    `exec \\\\$b --app=${url}; done; ` +
    // The same browsers installed as Flatpaks, which is how Mint and friends often carry them.
    'for f in com.brave.Browser com.google.Chrome org.chromium.Chromium com.microsoft.Edge ' +
    'com.vivaldi.Vivaldi; do flatpak info \\\\$f >/dev/null 2>&1 && ' +
    `exec flatpak run \\\\$f --app=${url}; done; exec xdg-open ${url}`;
  const exec = `sh -c "${script}"`;
  return [
    '[Desktop Entry]',
    'Type=Application',
    'Name=Whereabouts',
    'Comment=Where your phone is, and the people who share with you',
    `Exec=${exec}`,
    'Icon=mark-location',
    'Categories=Utility;',
    'Terminal=false',
    '',
  ].join('\n');
}
