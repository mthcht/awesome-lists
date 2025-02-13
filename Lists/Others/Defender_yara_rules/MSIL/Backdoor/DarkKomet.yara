rule Backdoor_MSIL_DarkKomet_KA_2147851486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DarkKomet.KA!MTB"
        threat_id = "2147851486"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Binded.exe" wide //weight: 1
        $x_1_2 = "C:\\Users" wide //weight: 1
        $x_1_3 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Win32Api.exe" wide //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

