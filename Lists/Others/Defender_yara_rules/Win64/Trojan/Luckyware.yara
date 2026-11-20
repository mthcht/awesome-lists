rule Trojan_Win64_Luckyware_AB_2147977244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Luckyware.AB!MTB"
        threat_id = "2147977244"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Luckyware"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {41 0f b7 c8 41 0f af c9 66 2b d1 66 33 d0 41 0f b7 c0 6b c8 ?? 48 8d 45 07 66 41 03 ca 66 33 d1}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Luckyware_AB_2147977244_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Luckyware.AB!MTB"
        threat_id = "2147977244"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Luckyware"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "https://i-like.boats/Stb/Retev.php" ascii //weight: 5
        $x_2_2 = "Start-Process -FilePath $env:APPDATA\\BK127533.exe -WindowStyle Hidden" ascii //weight: 2
        $x_2_3 = "[GHOST] Enter KeyAuth License Key:" ascii //weight: 2
        $x_1_4 = "x64dbg.exe" ascii //weight: 1
        $x_1_5 = "dnSpy.exe" ascii //weight: 1
        $x_1_6 = "processhacker.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

