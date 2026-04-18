rule Trojan_Win64_FlCollector_A_2147967287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FlCollector.A!dha"
        threat_id = "2147967287"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FlCollector"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Get-Process | Select Name,Id,Product,Description,ProductVersion,Path | fl" wide //weight: 1
        $x_1_2 = "Subject,Issuer,EnhancedKeyUsageList,NotBefore,NotAfter | fl" wide //weight: 1
        $x_1_3 = "\"select * from Win32_PnpEntity where ClassGuid = '{50DD5230-BA8A-11D1-BF5D-0000F805F530}'\" | select Name,PNPClass | fl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

