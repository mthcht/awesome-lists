# YAML Schema
A formal version of the below can be found [here](/.github/schema/schema.yml).

A simple template can be found [here](/template.yml).

| Field | Type | Required | Format | Description |
| ----- | ---- | -------- | ------ | ----------- |
| `Name`| String | ✅ | All lower case, must end in `.dll` | Name of the DLL that is being recorded. |
| `Author` | String | ✅ |  | Full name of the person creating the entry. |
| `Created` | Date| ✅ | YYYY-MM-DD | Date of when the entry was first created. |
| `Vendor` | String | ✅ |  | Name of the vendor providing the DLL. |
| `CVE` | String | Optional | CVE-YYYY-XXXX | ID of the assigned CVE, if applicable. |
| `ExpectedLocations` | List[String] | Optional | No trailing slashes | Folder locations[^1] where legitimate versions of the DLL are normally found. |
| `ExpectedVersionInformation` | [VersionInformation](#VersionInformation) | Optional | | File attributes of the legitimate DLL.|
| `ExpectedSignatureInformation` | [SignatureInformation](#SignatureInformation) | Optional | | Signature data of the legitimate DLL.|
| `VulnerableExecutables` | List[[VulnerableExecutable](#VulnerableExecutable)] | ✅ |  | Executables that are known to load the DLL described. |
| `Resources` | List[String] | Optional | HTTP(S) links only | URLs to relevant content that may explain further context (e.g. a PDF report, a tweet, a YouTube video).|
| `Acknowledgements` | List[[Acknowledgement](#Acknowledgement)] | Optional |  | People who should be acknowledge for finding this entry (i.e. who did the actual research). |

## VulnerableExecutable
| Field | Type | Required | Format | Description |
| ----- | ---- | -------- | ------ | ----------- |
| `Path` | String | ✅ | Has to end in `.exe` | Full location[^1] of legitimate executables that attempt to load the described DLL. |
| `Type` | String | ✅ | `Sideloading` \| `Phantom` \| `Search Order` \| `Environment Variable` | The type of DLL Hijacking this executable is vulnerable to. |
| `AutoElevate` | Boolean | Optional | `true` only | Only create this field and set to `true` if the executable is automatically elevated by Windows. |
| `PrivilegeEscalation` | Boolean | Optional | `true` only | Only create this field and set to `true` if the executable normally runs under elevated privileges. |
| `Condition` | String | Optional |  | If certain conditions are required for the attack to work, you can state them here. |
| `SHA256` | List[String] | Optional | 64 characters | If the executable is 3rd-party (i.e. non-Microsoft), please add the SHA256 hash(es) of the executable here. |
| `Variable` | String | Only when `Type` is set to `Environment Variable` | Should not contain percentage signs (`%`) | The environment variable name that can be hijacked. |
| `ExpectedVersionInformation` | [VersionInformation](#VersionInformation) | Optional |  | File attributes of the legitimate executable.|
| `ExpectedSignatureInformation` | [SignatureInformation](#SignatureInformation) | Optional | | Signature data of the legitimate executable.|

## VersionInformation
| Field | Type | Required | Format | Description |
| ----- | ---- | -------- | ------ | ----------- |
| CompanyName | String | Optional | | The `CompanyName` attribute of the PE file.|
| FileDescription | String | Optional | | The `FileDescription` attribute of the PE file.|
| FileVersion | String | Optional | | The `FileVersion` attribute of the PE file.|
| InternalName | String | Optional | | The `InternalName` attribute of the PE file.|
| LegalCopyright | String | Optional | | The `LegalCopyright` attribute of the PE file.|
| OriginalFilename | String | Optional | | The `OriginalFilename` attribute of the PE file.|
| ProductName | String | Optional | | The `ProductName` attribute of the PE file.|
| ProductVersion | String | Optional | | The `ProductVersion` attribute of the PE file.|

## SignatureInformation
| Field | Type | Required | Format | Description |
| ----- | ---- | -------- | ------ | ----------- |
| Subject | String | Optional | [DN format](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names)  | The expected subject of the certificate.|
| Issuer | String | Optional | [DN format](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names) | The expected issuer of the certificate.|
| Type | String | ✅ | `Authenticode` \| `Catalog` \| `None`  | The expected signature type. |

## Acknowledgement
| Field | Type | Required | Format | Description |
| ----- | ---- | -------- | ------ | ----------- |
| `Name` | String | ✅ |  | Full name (or Twitter screen name) of the person who should be acknowledged. |
| `Twitter` | String | Optional | Has to start with `@` | The Twitter handle of the person who should be acknowledged. |

[^1]: This field supports environment variables such as `%SYSTEM32%`, `%SYSWOW64%`, `%PROGRAMFILES%`, `%PROGRAMDATA%`, `%APPDATA%`, `%LOCALAPPDATA%`, and so on. Please use this where possible. Variable `%VERSION%` is also available if a path contains a version number that is likely to change.
