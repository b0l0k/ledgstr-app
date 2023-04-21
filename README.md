
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]

<div align="center">
  <a href="https://github.com/vbouzon/ledgstr-app">
    <img src="icons/icon-128.png" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">Ledgstr - App</h3>
</div>

# Concept

**STILL IN PoC STAGE.**
Based on Ledger boilerplate, **cleaning in progress**.

Ledger application aiming to manage your Nostr key in a secure way.  
Combined with the [Chrome extension](https://github.com/vbouzon/ledgstr-extension-chrome) using NIP-07, you can use your favoti Nostr web client.

## Ledger compatibility
 - Ledger Nano S - USB - Tested
 - Ledger Nano X - USB - Not tested

## Key principles
 - Use [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) & [SLIP-44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) for key generation (/44'/1237'/0')


# Roadmap

- [x] Key generation, based on [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) & [SLIP-44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)
- [x] Event signing with hash verification (optional)
- [ ] Direct message with NIP-04
- [ ] Test with Ledger Nano X on USB
- [ ] Nano X bluethooth support
- [ ] Slax support

# Technical notes
## Build

```sh
sudo docker run --rm -ti -v "$(realpath .):/app" --user $(id -u $USER):$(id -g $USER) ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder:latest
```

## Install


```sh
python3 -m ledgerblue.loadApp --curve secp256k1 --appFlags 0x000 --path "44'/1237'" --tlv --targetId 0x31100004 --targetVersion="2.1.0" --delete --fileName bin/app.hex --appName "Boilerplate" --appVersion "1.0.1" --dataSize $((0x`cat debug/app.map |grep _envram_data | tr -s ' ' | cut -f2 -d' '|cut -f2 -d'x'` - 0x`cat debug/app.map |grep _nvram_data | tr -s ' ' | cut -f2 -d' '|cut -f2 -d'x'`)) `ICONHEX=\`python3 /opt/nanos-secure-sdk/icon3.py --hexbitmaponly icons/nanos_app_boilerplate.gif  2>/dev/null\` ; [ ! -z "$ICONHEX" ] && echo "--icon $ICONHEX"` 
```


## Contact

Vincent Bouzon - [@vincent](https://nostr.band/npub1umpngr838pwy3hgevlpgkuprfe6jsfzm8syf5cqm8eppwmhh69sq6e7a5s)

Project Link: [https://github.com/vbouzon/ledgstr-app](https://github.com/vbouzon/ledgstr-app)

<!-- ACKNOWLEDGMENTS -->

## Acknowledgments

- [Ledger boilerplate](https://github.com/LedgerHQ/app-boilerplate)
- My wife for the beautiful logo and her eternal support.


[contributors-shield]: https://img.shields.io/github/contributors/vbouzon/ledgstr-app.svg?style=for-the-badge
[contributors-url]: https://github.com/vbouzon/ledgstr-app/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/vbouzon/ledgstr-app.svg?style=for-the-badge
[forks-url]: https://github.com/vbouzon/ledgstr-app/network/members
[stars-shield]: https://img.shields.io/github/stars/vbouzon/ledgstr-app.svg?style=for-the-badge
[stars-url]: https://github.com/vbouzon/ledgstr-app/stargazers
[issues-shield]: https://img.shields.io/github/issues/vbouzon/ledgstr-app.svg?style=for-the-badge
[issues-url]: https://github.com/vbouzon/ledgstr-app/issues
[license-shield]: https://img.shields.io/github/license/vbouzon/ledgstr-app.svg?style=for-the-badge
[license-url]: https://github.com/vbouzon/ledgstr-app/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/bouzon
[product-screenshot]: images/screenshot.png
[Next.js]: https://img.shields.io/badge/next.js-000000?style=for-the-badge&logo=nextdotjs&logoColor=white
[Next-url]: https://nextjs.org/
[React.js]: https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB
[React-url]: https://reactjs.org/
[Vue.js]: https://img.shields.io/badge/Vue.js-35495E?style=for-the-badge&logo=vuedotjs&logoColor=4FC08D
[Vue-url]: https://vuejs.org/
[Angular.io]: https://img.shields.io/badge/Angular-DD0031?style=for-the-badge&logo=angular&logoColor=white
[Angular-url]: https://angular.io/
[Svelte.dev]: https://img.shields.io/badge/Svelte-4A4A55?style=for-the-badge&logo=svelte&logoColor=FF3E00
[Svelte-url]: https://svelte.dev/
[Laravel.com]: https://img.shields.io/badge/Laravel-FF2D20?style=for-the-badge&logo=laravel&logoColor=white
[Laravel-url]: https://laravel.com
[Bootstrap.com]: https://img.shields.io/badge/Bootstrap-563D7C?style=for-the-badge&logo=bootstrap&logoColor=white
[Bootstrap-url]: https://getbootstrap.com
[JQuery.com]: https://img.shields.io/badge/jQuery-0769AD?style=for-the-badge&logo=jquery&logoColor=white
[JQuery-url]: https://jquery.com
