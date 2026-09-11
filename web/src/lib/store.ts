import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import { storeKeys, clearKeys, getKeys, storeKeysFor, getKeysFor, deleteKeysFor } from '@/lib/keystore';
import type { Location } from '@/lib/api';
import type { Language } from '@/lib/i18n';

export type Theme = 'light' | 'dark' | 'system';
export type UnitSystem = 'metric' | 'imperial';
export type { Language } from '@/lib/i18n';

interface UserData {
  fmdId: string;
  sessionToken: string;
  rsaEncKey: CryptoKey;
  rsaSigKey: CryptoKey;
  fingerprint: string;
}

/**
 * A second, third, ... phone whose location is shown beside your own.
 *
 * Its private key is unwrapped from its own password in this browser, exactly
 * as the primary device's is, so the server still holds nothing it can read.
 * What is kept here is the cost of that: this browser can decrypt every device
 * it has been given, so whoever holds this browser holds the family's map.
 */
export interface Companion {
  fmdId: string;
  label: string;
  sessionToken: string;
  rsaEncKey: CryptoKey;
  rsaSigKey: CryptoKey;
  /** Latest known position, decrypted here. Null until first fetched. */
  latest: Location | null;
}

interface AppState {
  isLoggedIn: boolean;
  userData: UserData | null;
  companions: Companion[];
  wasAuthRestoreTried: boolean;
  theme: Theme;
  units: UnitSystem;
  language: Language;
  pushUrl: string | null;
  isPushUrlLoading: boolean;

  locations: Location[];
  currentLocationIndex: number;
  isLocationsLoading: boolean;

  pictures: string[];
  isPicturesLoading: boolean;

  setUserData: (data: UserData, persistent: boolean) => Promise<void>;
  addCompanion: (c: Omit<Companion, 'latest'>) => Promise<void>;
  removeCompanion: (fmdId: string) => Promise<void>;
  setCompanionLatest: (fmdId: string, latest: Location | null) => void;
  restoreCompanions: () => Promise<void>;
  logout: () => Promise<void>;
  restoreAuth: () => Promise<void>;
  setTheme: (theme: Theme) => void;
  setLanguage: (language: Language) => void;
}

const KEY_AUTH = 'fmd-auth';
const KEY_COMPANIONS = 'fmd-companions';
const KEY_SETTINGS = 'fmd-settings';

export const useStore = create<AppState>()(
  persist(
    (set) => ({
      isLoggedIn: false,
      userData: null,
      companions: [],
      wasAuthRestoreTried: false,
      theme: 'system',
      units: 'metric',
      language: 'en',
      pushUrl: null,
      locations: [],
      currentLocationIndex: 0,
      pictures: [],
      isPushUrlLoading: false,
      isLocationsLoading: false,
      isPicturesLoading: false,

      setUserData: async (data: UserData, persistent: boolean) => {
        if (persistent) {
          await storeKeys({
            rsaEncKey: data.rsaEncKey,
            rsaSigKey: data.rsaSigKey,
          });

          localStorage.setItem(
            KEY_AUTH,
            JSON.stringify({
              fmdId: data.fmdId,
              sessionToken: data.sessionToken,
              fingerprint: data.fingerprint,
            })
          );
        }

        set({
          userData: data,
          isLoggedIn: true,
        });
      },

      addCompanion: async (c) => {
        await storeKeysFor(c.fmdId, { rsaEncKey: c.rsaEncKey, rsaSigKey: c.rsaSigKey });

        const stored = JSON.parse(localStorage.getItem(KEY_COMPANIONS) || '[]') as Array<{
          fmdId: string;
          label: string;
          sessionToken: string;
        }>;
        const others = stored.filter((e) => e.fmdId !== c.fmdId);
        others.push({ fmdId: c.fmdId, label: c.label, sessionToken: c.sessionToken });
        localStorage.setItem(KEY_COMPANIONS, JSON.stringify(others));

        set((state) => ({
          companions: [
            ...state.companions.filter((x) => x.fmdId !== c.fmdId),
            { ...c, latest: null },
          ],
        }));
      },

      removeCompanion: async (fmdId: string) => {
        await deleteKeysFor(fmdId);
        const stored = JSON.parse(localStorage.getItem(KEY_COMPANIONS) || '[]') as Array<{
          fmdId: string;
        }>;
        localStorage.setItem(
          KEY_COMPANIONS,
          JSON.stringify(stored.filter((e) => e.fmdId !== fmdId))
        );
        set((state) => ({ companions: state.companions.filter((c) => c.fmdId !== fmdId) }));
      },

      setCompanionLatest: (fmdId: string, latest: Location | null) => {
        set((state) => ({
          companions: state.companions.map((c) => (c.fmdId === fmdId ? { ...c, latest } : c)),
        }));
      },

      restoreCompanions: async () => {
        try {
          const stored = JSON.parse(localStorage.getItem(KEY_COMPANIONS) || '[]') as Array<{
            fmdId: string;
            label: string;
            sessionToken: string;
          }>;
          const restored: Companion[] = [];
          for (const entry of stored) {
            const keys = await getKeysFor(entry.fmdId);
            // A companion whose keys are gone cannot be decrypted, so drop it
            // rather than show a device that will never report.
            if (!keys) continue;
            restored.push({
              fmdId: entry.fmdId,
              label: entry.label,
              sessionToken: entry.sessionToken,
              rsaEncKey: keys.rsaEncKey,
              rsaSigKey: keys.rsaSigKey,
              latest: null,
            });
          }
          set({ companions: restored });
        } catch {
          localStorage.removeItem(KEY_COMPANIONS);
        }
      },

      logout: async () => {
        localStorage.removeItem(KEY_AUTH);
        await clearKeys();
        // Logging out means logging out: the companions' keys go with it, or
        // whoever opens this browser next still holds the family's map.
        for (const c of useStore.getState().companions) {
          await deleteKeysFor(c.fmdId);
        }
        localStorage.removeItem(KEY_COMPANIONS);
        set({
          userData: null,
          companions: [],
          isLoggedIn: false,
          pushUrl: null,
          locations: [],
          pictures: [],
        });
      },

      restoreAuth: async () => {
        try {
          const authData = localStorage.getItem(KEY_AUTH);
          if (!authData) return;

          const parsed = JSON.parse(authData) as {
            fmdId: string;
            sessionToken: string;
            fingerprint: string;
          };
          const keys = await getKeys();

          if (keys) {
            set({
              userData: {
                fmdId: parsed.fmdId,
                sessionToken: parsed.sessionToken,
                rsaEncKey: keys.rsaEncKey,
                rsaSigKey: keys.rsaSigKey,
                fingerprint: parsed.fingerprint,
              },
              isLoggedIn: true,
            });
          }
        } catch {
          localStorage.removeItem(KEY_AUTH);
          await clearKeys();
        } finally {
          set({ wasAuthRestoreTried: true });
        }
      },

      setTheme: (theme: Theme) => {
        set({ theme });

        const isDark =
          theme === 'dark' ||
          (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);

        document.documentElement.classList.toggle('dark', isDark);
      },

      setLanguage: (language: Language) => {
        set({ language });
        // Language change is synced from main.tsx Root component
      },
    }),

    // Persist some of the state
    // https://github.com/pmndrs/zustand/blob/main/docs/integrations/persisting-store-data.md
    {
      name: KEY_SETTINGS,
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        theme: state.theme,
        units: state.units,
        language: state.language,
      }),
    }
  )
);

export const logout = () => useStore.getState().logout();
