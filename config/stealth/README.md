# Shikra Stealth System

## Directory Structure

### Levels (config/stealth/levels/)
- `0_disabled.json` - No stealth measures
- `1_basic.json` - Basic VM hiding
- `2_standard.json` - Standard anti-detection
- `3_advanced.json` - Advanced evasion
- `4_paranoid.json` - Maximum stealth

### Hardware Profiles (config/stealth/hardware_profiles/)
- `dell_optiplex.json` - Dell OptiPlex system profile
- `lenovo_thinkpad.json` - Lenovo ThinkPad profile  
- `hp_elitebook.json` - HP EliteBook profile

### Detection Signatures (config/stealth/detection_signatures/)
- `vm_artifacts.json` - Known VM artifacts to hide
- `known_indicators.json` - VM detection indicators

## Usage

### Apply Stealth During VM Creation
```bash
# In create_vm.sh
scripts/stealth/apply_stealth.sh --vm-name "$VM_NAME" --level 3 --profile "dell_optiplex"
```

### Validate Stealth Effectiveness
```bash
scripts/stealth/validate_stealth.sh --vm-name "$VM_NAME"
```

### Python Validation (Advanced)
```python
from core.modules.vm_controller.stealth_validator import StealthValidator
validator = StealthValidator()
report = validator.validate_vm_stealth("vm_name")
```

## Integration Points

1. **VM Creation** - `create_vm.sh` calls `apply_stealth.sh`
2. **Analysis** - Python modules validate stealth effectiveness
3. **Reporting** - Stealth reports integrated with analysis results
