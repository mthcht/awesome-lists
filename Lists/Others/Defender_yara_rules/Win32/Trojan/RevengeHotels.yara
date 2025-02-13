rule Trojan_Win32_RevengeHotels_SP_2147745760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevengeHotels.SP!MSR"
        threat_id = "2147745760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevengeHotels"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "winmgmts:\\\\localhost\\root\\cimv2" wide //weight: 1
        $x_1_2 = "SELECT * FROM Win32_OperatingSystem" wide //weight: 1
        $x_1_3 = "filtro.cfg" wide //weight: 1
        $x_1_4 = "B6589FC6AB0DC82CF12099D1C2D40AB994E8410C" wide //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_RevengeHotels_SQ_2147745761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevengeHotels.SQ!MSR"
        threat_id = "2147745761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevengeHotels"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "{9B3B2670-EFE7-4C06-B60E-575DBD0BE84F" ascii //weight: 1
        $x_1_2 = "{61E9945D-84C0-48BD-847D-A5EA3AF829B9" ascii //weight: 1
        $x_1_3 = "$0233EB08-CA97-4B68-BE27-8ABD14E1E7F8" ascii //weight: 1
        $x_1_4 = {53 00 63 00 72 00 65 00 65 00 6e 00 42 00 6f 00 6f 00 6b 00 69 00 6e 00 67 00 90 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = "SendBlaster" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

