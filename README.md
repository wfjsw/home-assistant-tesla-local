# Tesla BLE - Home Assistant Integration

[![HACS](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
[![GitHub Release](https://img.shields.io/github/release/home-assistant-tesla-local/home-assistant-tesla-ble.svg)](https://github.com/home-assistant-tesla-local/home-assistant-tesla-ble/releases)
[![License](https://img.shields.io/github/license/home-assistant-tesla-local/home-assistant-tesla-ble.svg)](LICENSE)

A native Home Assistant integration for controlling Tesla vehicles via Bluetooth Low Energy (BLE). This integration uses Home Assistant's Bluetooth API and supports Bluetooth Proxies for extended range.

## Features

- **Native Bluetooth Integration**: Uses Home Assistant's Bluetooth API for seamless integration
- **Bluetooth Proxy Support**: Works with ESPHome Bluetooth Proxies for extended range
- **Automatic Discovery**: Discovers nearby Tesla vehicles automatically
- **Secure Key Pairing**: Integrated key registration flow with NFC card authentication
- **No Cloud Required**: All communication is local via Bluetooth

## Supported Features

### Controls
- 🔐 Lock/Unlock vehicle
- 🚗 Wake vehicle
- 📦 Open/Close trunk
- 🛻 Open frunk
- ⚡ Open/Close charge port

### Sensors
- Door states (all doors)
- Trunk/Frunk status
- Charge port status
- Lock state
- Sleep status
- User presence
- BLE connection status

## Requirements

- Home Assistant 2024.1.0 or newer
- Bluetooth adapter or ESPHome Bluetooth Proxy
- Tesla vehicle with BLE support (Model S/X 2021+, Model 3/Y all years)
- Tesla key card for initial pairing

## Installation

### HACS (Recommended)

1. Open HACS in Home Assistant
2. Click the three dots in the top right corner
3. Select "Custom repositories"
4. Add this repository URL and select "Integration" as the category
5. Click "Add"
6. Search for "Tesla BLE" and install it
7. Restart Home Assistant

### Manual Installation

1. Download the latest release from GitHub
2. Copy the `custom_components/tesla_ble` folder to your Home Assistant `custom_components` directory
3. Restart Home Assistant

## Configuration

### Adding a Vehicle

1. Go to **Settings** → **Devices & Services**
2. Click **+ Add Integration**
3. Search for "Tesla BLE"
4. Select your Tesla vehicle from the discovered devices
5. Choose to generate a new key or import an existing one
6. Enter your vehicle's VIN
7. When prompted, tap your Tesla key card on the center console to authorize the new key

### Using Bluetooth Proxies

This integration fully supports [ESPHome Bluetooth Proxies](https://esphome.io/components/bluetooth_proxy.html). To use a Bluetooth Proxy:

1. Set up an ESPHome device with Bluetooth Proxy enabled
2. The Tesla vehicle will be discovered through the proxy
3. All BLE communication will be routed through the proxy

This is useful if your Home Assistant server is not within Bluetooth range of your vehicle.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Home Assistant                          │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐   │
│  │                  Tesla BLE Integration                │   │
│  ├──────────────────────────────────────────────────────┤   │
│  │  Config Flow    │  Coordinator   │  Entities          │   │
│  │  - Discovery    │  - Connection  │  - Lock            │   │
│  │  - Key Pairing  │  - Polling     │  - Buttons         │   │
│  │  - VIN Entry    │  - Commands    │  - Sensors         │   │
│  └──────────────────────────────────────────────────────┘   │
│                           │                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │               Tesla BLE Protocol                      │   │
│  ├──────────────────────────────────────────────────────┤   │
│  │  Crypto        │  Messages      │  Vehicle API        │   │
│  │  - ECDH        │  - Protobuf    │  - Lock/Unlock      │   │
│  │  - AES-GCM     │  - VCSEC       │  - Trunk/Frunk      │   │
│  │  - HKDF        │  - Routing     │  - Status           │   │
│  └──────────────────────────────────────────────────────┘   │
│                           │                                  │
├───────────────────────────┼──────────────────────────────────┤
│               Home Assistant Bluetooth API                   │
│                           │                                  │
│  ┌────────────────┐  or  ┌────────────────────────────┐     │
│  │ Local Adapter  │      │ ESPHome Bluetooth Proxy    │     │
│  └────────────────┘      └────────────────────────────┘     │
└───────────────────────────┼──────────────────────────────────┘
                            │
                    ┌───────┴───────┐
                    │ Tesla Vehicle │
                    │   (BLE)       │
                    └───────────────┘
```

## Protocol Details

This integration implements Tesla's BLE protocol as documented in the [tesla-vehicle-command](https://github.com/teslamotors/vehicle-command) repository:

- **Service UUID**: `00000211-b2d1-43f0-9b88-960cebf8b91e`
- **TX Characteristic**: `00000212-b2d1-43f0-9b88-960cebf8b91e`
- **RX Characteristic**: `00000213-b2d1-43f0-9b88-960cebf8b91e`

### Security

- Uses ECDH (P-256) for key exchange
- AES-GCM for message encryption
- HKDF for session key derivation
- All keys are stored securely in Home Assistant's configuration

## Troubleshooting

### Vehicle not discovered

1. Make sure your vehicle is awake (check the Tesla app)
2. Ensure Bluetooth is enabled on your Home Assistant server or proxy
3. Move closer to the vehicle or use a Bluetooth Proxy

### Key pairing fails

1. Make sure you're sitting inside the vehicle
2. Place the key card on the center console reader
3. Wait for the full 30 seconds timeout
4. Try waking the vehicle first through the Tesla app

### Commands not working

1. Check that the key is properly paired (try locking/unlocking from the Tesla app using the key name)
2. Ensure the vehicle is awake
3. Check the Home Assistant logs for error messages

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This integration is not affiliated with, endorsed by, or connected to Tesla, Inc. Use at your own risk.

## Credits

- [Tesla Vehicle Command](https://github.com/teslamotors/vehicle-command) - Official Tesla BLE protocol documentation
- [tesla_ble_mqtt_core](https://github.com/tesla-local-control/tesla_ble_mqtt_core) - Reference implementation
- [esphome-tesla-ble](https://github.com/PedroKTFC/esphome-tesla-ble) - ESPHome implementation reference
