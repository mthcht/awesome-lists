rule Trojan_Win32_MuddyWaterz_A_2147965417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MuddyWaterz.A!MTB"
        threat_id = "2147965417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MuddyWaterz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "data:application/javascript;base64," wide //weight: 1
        $x_1_2 = "deno.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

