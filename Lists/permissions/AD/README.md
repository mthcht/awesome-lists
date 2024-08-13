## Monitor Critical AD Groups

Monitors and detects modifications to privileged Active Directory groups to prevent unauthorized access using my list and these Security Event IDs:

- **4727:** A security-enabled global group was created.
- **4728:** A member was added to a security-enabled global group.
- **4731:** A security-enabled local group was created.
- **4732:** A member was added to a security-enabled local group.
- **4737:** A security-enabled global group was changed.
- **4744:** A security-disabled local group was created.
- **4749:** A security-disabled global group was created.
- **4754:** A security-enabled universal group was created.
- **4755:** A security-enabled universal group was changed.
- **4756:** A member was added to a security-enabled universal group.
- **4759:** A security-disabled universal group was created.
- **4783:** A security-enabled global group was deleted.
- **4790:** An LDAP query group was changed.

I initially shared my list on Twitter here: https://x.com/mthcht/status/1818196168515461431, and then updated this README accordingly, let me know if i should include something else for the detection

### Splunk Search:

**Best detection using only the AD group SID**
```sql
`wineventlog`
  signature_id IN (4727,4728,4731,4732,4737,4744,4749,4754,4755,4756,4759,4783,4790)
  [|inputlookup windows_sensitives_ad_groups_list.csv | table dest_group_id]
```

**Detection using only the AD group names** (group names can differ depending on the language selected during the DC installation)
```sql
`wineventlog`
  signature_id IN (4727,4728,4731,4732,4737,4744,4749,4754,4755,4756,4759,4783,4790)
  [|inputlookup windows_sensitives_ad_groups_list.csv | table dest_group]
```

**Detecting modifications with the group name or group SID**
```sql
`wineventlog`
  signature_id IN (4727,4728,4731,4732,4737,4744,4749,4754,4755,4756,4759,4783,4790)
  [|inputlookup windows_sensitives_ad_groups_list.csv | table dest_group] OR [|inputlookup windows_sensitives_ad_groups_list.csv | table dest_group_id]
```

