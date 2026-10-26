# netsec-snort-noise

Root filesystem overlay for the hidden background-traffic VM in the PolyLab
three-stage Snort exercise.

The payload creates five deterministic source identities and generates low-rate
benign UDP and HTTP traffic. It uses the same `snort-attacker` Buildroot
baseline; no separate script 02 feature set is required.

Package it with `buildroot-builder2` script 03:

```sh
scripts/03-package-payload.sh \
  --baseline artifacts/<snort-attacker-artifact> \
  --repo https://github.com/giacobe/netsec-snort-noise \
  --ref main \
  --payload-subdir rootfs-overlay \
  --archive-dest / \
  --permissions-file permissions.txt \
  --output-prefix packaged-noise \
  --output packaged \
  --force
```

Verify the payload bytes on Linux with:

```sh
sha256sum -c SHA256SUMS
```

