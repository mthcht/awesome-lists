rule Trojan_Win32_NJRat_MK_2147754357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NJRat.MK!MSR"
        threat_id = "2147754357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NJRat"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$URL = \"http://dark.crypterfile.com/9.zip\"" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

