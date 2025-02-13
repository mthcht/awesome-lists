rule Trojan_MSIL_EvilCrypt_PAA_2147810972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/EvilCrypt.PAA!MTB"
        threat_id = "2147810972"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "EvilCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /im wininit.exe /f" wide //weight: 1
        $x_1_2 = "CryptoVirus Detected!  Ransom." wide //weight: 1
        $x_1_3 = "vssadmin delete shadows /all /quiet & wmic shadowcopy delete" wide //weight: 1
        $x_1_4 = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableRegistryTools /t REG_DWORD /d 0 /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

