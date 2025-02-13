rule PUA_Win32_Camnori_Lowfi_222292_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:Win32/Camnori!Lowfi"
        threat_id = "222292"
        type = "PUA"
        platform = "Win32: Windows 32-bit platform"
        family = "Camnori"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "300"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@Software\\Camnori" wide //weight: 1
        $x_1_2 = "m=%s&p=%s&d=%s&w=%s&h=%s&cp=%s" wide //weight: 1
        $x_1_3 = "app.sidejet.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

