# Flownix

Flonwix is a graphical network traffic analyzer for Linux-based systems that relies on [ptcpdump](https://github.com/mozillazg/ptcpdump)

<p float="left">
  <img src="docs/assets/overview_1.png" width="45%" style="margin-right:5%" />
  <img src="docs/assets/overview_2.png" width="45%" />
</p>

## 📝 Overview

**Flownix** is a **graphical**, **realtime**, **flow-based network traffic analyzer** for Linux systems.
It captures packets using the **ptcpdump** binary, extracts detailed metadata about each flow, stores it in SQLite, and visualizes everything in a clean, responsive Dash web interface.

## 🚀 Features

+ Support secure remote forwarding using websocket
+ Provide sorting & query filtering for dash table

## 📦 Installation

You can download the latest `.deb` file from the [releases](https://github.com/VISION-183/flownix/releases) section.

## ▶️ Usage

After installing, simply open your browser at: `http://localhost:8050`

## ⚙️ Build

+ There are ready to go [PyInstaller](./pyinstaller/) spec files
+ [Debian packaging structure](./deb/) are included for building distributable packages

## 🔧 Development

+ Project requires `python3.9` at least. Higher versions are not tested
+ Use the provided [requirements.txt](./requirements.txt) for development setup

## 🧾 License

Flownix is licensed under the Apache License 2.0.
See the [LICENSE](./LICENSE) and [NOTICE](./NOTICE) files for details.

## 🙏 Acknowledgments

Packet capturing provided by [ptcpdump](https://github.com/mozillazg/ptcpdump)