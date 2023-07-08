<!-- Improved compatibility of back to top link: See: https://github.com/othneildrew/Best-README-Template/pull/73 -->
<a name="readme-top"></a>
<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![Apache 2.0 License][license-shield]][license-url]



<!-- PROJECT LOGO -->
<br />
<div align="center">

<h3 align="center">sSocks</h3>

  <p align="center">
    A tiny socks5 VPN
    <br />
    <a href="https://github.com/Hackerl/sSocks/wiki"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/Hackerl/sSocks/issues">Report Bug</a>
    ·
    <a href="https://github.com/Hackerl/sSocks/issues">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#build">Build</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

A tiny socks5 VPN based on TLS mutual authentication.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



### Built With

* [![CMake][CMake]][CMake-url]
* [![vcpkg][vcpkg]][vcpkg-url]
* [![C++17][C++17]][C++17-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started

Both the server and the client need their own private keys and certificates when deployed.

### Prerequisites

Create openssl 509 extended configuration, then generate all keys and certificates needed.

* ext.cnf
  ```conf
  [req]
  distinguished_name = req_distinguished_name
  req_extensions = v3_req
  
  [req_distinguished_name]
  
  [v3_req]
  subjectAltName = @alt_names
  
  [alt_names]
  IP.1 = YOUR_SERVER_IP.1
  IP.2 = YOUR_SERVER_IP.2
  ```

* private keys and certificates
  ```sh
  openssl genrsa -out cakey.pem 2048
  openssl req -new -key cakey.pem -out ca.csr -subj "/C=CN/ST=province/L=city/O=organization/OU=group/CN=CA"
  openssl x509 -req -days 365 -sha256 -extensions v3_ca -signkey cakey.pem -in ca.csr -out  cacert.pem
  openssl genrsa -out server-key.pem 2048
  openssl req -new -key server-key.pem -out server.csr -subj "/C=CN/ST=province/L=city/O=organization/OU=group/CN=server"
  openssl x509 -req -days 365 -sha256 -extensions v3_req -extfile ext.cnf -CA cacert.pem -CAkey cakey.pem -CAserial ca.srl -CAcreateserial -in server.csr -out server-cert.pem
  openssl verify -CAfile cacert.pem server-cert.pem
  openssl genrsa  -out client-key.pem 2048
  openssl req -new -key client-key.pem -out client.csr -subj "/C=CN/ST=province/L=city/O=organization/OU=group/CN=client"
  openssl x509 -req -days 365 -sha256 -extensions v3_req -CA  cacert.pem -CAkey cakey.pem  -CAserial ca.srl -in client.csr -out client-cert.pem
  ```

### Build

* Linux
  ```sh
  mkdir -p build && cmake -B build -DCMAKE_TOOLCHAIN_FILE="${VCPKG_INSTALLATION_ROOT}/scripts/buildsystems/vcpkg.cmake" && cmake --build build -j$(nproc)
  ```

* Android
  ```sh
  # set "ANDROID_PLATFORM" for dependencies installed by vcpkg: echo 'set(VCPKG_CMAKE_SYSTEM_VERSION 24)' >> "${VCPKG_INSTALLATION_ROOT}/triplets/community/arm64-android.cmake"
  mkdir -p build && cmake -B build -DCMAKE_TOOLCHAIN_FILE="${VCPKG_INSTALLATION_ROOT}/scripts/buildsystems/vcpkg.cmake" -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE="${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake" -DVCPKG_TARGET_TRIPLET=arm64-android -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 && cmake --build build -j$(nproc)
  ```

* Windows(Developer PowerShell)
  ```sh
  mkdir -p build && cmake -B build -G Ninja -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake" && cmake --build build -j $env:NUMBER_OF_PROCESSORS
  ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage

* Server
  ```sh
  ./server 0.0.0.0 443 cacert.pem server-cert.pem server-key.pem
  ```

* Client

  ```sh
  ./client server-ip 443 cacert.pem client-cert.pem client-key.pem
  ```

* Proxy

  ```sh
  curl -x socks5://127.0.0.1:1080 https://www.google.com -vv
  ```

_For more examples, please refer to the [Documentation](https://github.com/Hackerl/sSocks/wiki)_

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ROADMAP -->
## Roadmap

See the [open issues](https://github.com/Hackerl/sSocks/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- LICENSE -->
## License

Distributed under the Apache 2.0 License. See `LICENSE` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTACT -->
## Contact

Hackerl - [@Hackerl](https://github.com/Hackerl) - patteliu@gmail.com

Project Link: [https://github.com/Hackerl/sSocks](https://github.com/Hackerl/sSocks)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* [aio](https://github.com/hackerl/aio)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/Hackerl/sSocks.svg?style=for-the-badge
[contributors-url]: https://github.com/Hackerl/sSocks/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/Hackerl/sSocks.svg?style=for-the-badge
[forks-url]: https://github.com/Hackerl/sSocks/network/members
[stars-shield]: https://img.shields.io/github/stars/Hackerl/sSocks.svg?style=for-the-badge
[stars-url]: https://github.com/Hackerl/sSocks/stargazers
[issues-shield]: https://img.shields.io/github/issues/Hackerl/sSocks.svg?style=for-the-badge
[issues-url]: https://github.com/Hackerl/sSocks/issues
[license-shield]: https://img.shields.io/github/license/Hackerl/sSocks.svg?style=for-the-badge
[license-url]: https://github.com/Hackerl/sSocks/blob/master/LICENSE
[CMake]: https://img.shields.io/badge/CMake-000000?style=for-the-badge&logo=cmake&logoColor=FF3E00
[CMake-url]: https://cmake.org
[vcpkg]: https://img.shields.io/badge/vcpkg-000000?style=for-the-badge&logo=microsoft&logoColor=61DAFB
[vcpkg-url]: https://vcpkg.io
[C++17]: https://img.shields.io/badge/C++17-000000?style=for-the-badge&logo=cplusplus&logoColor=4FC08D
[C++17-url]: https://en.cppreference.com/w/cpp/17