rule Trojan_Win32_Tuscas_CCIB_2147912337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tuscas.CCIB!MTB"
        threat_id = "2147912337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tuscas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "37b7e925-d34d-4d3f-93a4-17af93a01711" wide //weight: 1
        $x_1_2 = "%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x" wide //weight: 1
        $x_1_3 = "CustomAction.exe" wide //weight: 1
        $x_1_4 = "VALUES (%s, %s, %s)" wide //weight: 1
        $x_1_5 = "ValidatePID" wide //weight: 1
        $x_1_6 = "hvierxvh.vcv" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

