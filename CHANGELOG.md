# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.0.1] - 2023-10-10
### Fixed
- Fixed issue with DNS packet parsing causing incorrect results.
- Resolved memory leak in the packet capture module.

## [1.0.0] - 2023-10-01
### Added
- Initial release of DnsSniffer.
- Added support for capturing DNS packets.
- Implemented basic filtering for DNS queries and responses.
- Added logging functionality for captured DNS traffic.
- Included documentation for setup and usage.

### Changed
- Improved performance of packet capture by optimizing buffer handling.

### Fixed
- Corrected issue with incorrect timestamp on captured packets.

[Unreleased]: https://github.com/yourusername/DnsSniffer/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/yourusername/DnsSniffer/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/yourusername/DnsSniffer/releases/tag/v1.0.0