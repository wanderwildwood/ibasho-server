# Whereabouts server (ibasho-server)

The server half of [Whereabouts](https://github.com/wanderwildwood/ibasho): a fork of
[FMD Server](https://gitlab.com/fmd-foss/fmd-server) that adds one thing, a map of the
other people who share their location with you, and gives the web page a plain
ink-on-paper look.

Everything FMD Server does, this does. A phone running Whereabouts or the original FMD
app registers an account, uploads its location encrypted with a password only its owner
knows, and takes commands such as *ring* from the web page. The server stores only what
it cannot read.

## What this adds

**Other devices.** Under the device panel, add another account on the same server by its
id and password, and its latest location shows on your map as a named dot, with when it
was last seen and its battery. The password is the consent: someone who gives you theirs
is choosing to be on your map, and can leave it by changing it.

Each added device keeps its own session and keys in your browser, apart from your own
login. What is kept is the password *hash* the server asks for at log-in, never the
password, so an expired session can renew itself. If the hash is refused, the password has
changed: the page asks for the new one and stops trying, because the server locks an
account after a handful of failures. Logging out forgets every added device.

**An iPhone, through Overland.** There is no iPhone version of Whereabouts. Instead, an
iPhone runs [Overland](https://overland.p3k.app/) and posts its location to the small
bridge in [`overland/`](overland), which encrypts each point into that phone's account
exactly as the Android app would. The bridge sees each point before encrypting it; that is
the price of an iPhone taking part without an app of its own. It cannot send the iPhone
commands.

**The look.** Ink on paper, and a real dark theme; Lato; no animation; a greyscale map.
The page can be installed as an app, and a switch in the header picks automatic, light or
dark.

## Running it

Build and run with Docker. The image carries the web page and the server in one binary.

```bash
git clone https://github.com/wanderwildwood/ibasho-server
cd ibasho-server
docker build -t ibasho-server .
mkdir db && sudo chown 1000:1000 db   # the server runs as uid 1000 inside the image
docker run -d --name ibasho -p 8080:8080 \
  -v ./db:/var/lib/fmd-server/db \
  ibasho-server serve --db-dir /var/lib/fmd-server/db
```

The web page needs HTTPS: browsers only offer the WebCrypto the page decrypts with on a
secure origin, and the app refuses plain HTTP too. Put it behind a reverse proxy such as
Caddy with a certificate. `config.example.yml` lists the settings; set a
`RegistrationToken` so that strangers cannot make accounts, and `RemoteIpHeader` if a
proxy sits in front, or the login lockout sees only the proxy.

FMD's own [installation guide](https://fmd-foss.org/docs/fmd-server/installation/overview)
covers the rest and applies here unchanged.

### The Overland bridge

```bash
cd overland
go build -o fmd-overland .
./fmd-overland register -fmd-url http://127.0.0.1:8080 -user <account> -password <password> \
  -registration-token <token> -endpoint https://<your server>/overland
```

`register` makes the account and prints a device entry for the bridge's config file, and an
`overland://setup` link that configures Overland on the iPhone in one tap. Then run
`fmd-overland serve -config <file>` and route only `/overland` to it from the proxy. Its
`/status` page names the devices, so keep that private.

## Credit

This is FMD Server by Nulide, Thore Goebel and its contributors. **Nearly all of the code
is theirs**: the protocol, the encryption, the API and the web page this restyles. If it is
useful to you, [support FMD](https://liberapay.com/FMD/donate).

## Licence

GNU General Public License, version 3 or later, the same as upstream. See [LICENSE](LICENSE).
