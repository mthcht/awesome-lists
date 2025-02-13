rule Trojan_O97M_Offink_A_2147723352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Offink.A"
        threat_id = "2147723352"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Offink"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iex(Invoke-RestMethod -Uri 'https://COLLECTOR_URL/api/File'" ascii //weight: 1
        $x_1_2 = "objShell.Run (\"powershell.exe -WindowStyle Hidden" ascii //weight: 1
        $x_1_3 = "-Method Get -Headers @{'Guid'='" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

