rule TrojanDownloader_MSIL_RedLine_NWS_2147835003_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLine.NWS!MTB"
        threat_id = "2147835003"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 95 02 34 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 34 00 00 00 60 1b 00 00 2b 00 00 00 f7 36 00 00 02 00 00 00 3e 00 00 00 10 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = "$d1cc2bad-d6f7-47b8-afa8-3a9d4430dcc1" ascii //weight: 1
        $x_1_3 = "l7Wx0R8Lf82jGtw8" ascii //weight: 1
        $x_1_4 = "pSMq6YIM349l9JB9" ascii //weight: 1
        $x_1_5 = "WinDll.exe" ascii //weight: 1
        $x_1_6 = "ConfuserEx v1.0.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLine_NZT_2147837415_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLine.NZT!MTB"
        threat_id = "2147837415"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cHM6Ly9vbmUubGl0ZXNoYXJlLmNvL2Rvd25sb2FkLnBocD9" ascii //weight: 1
        $x_1_2 = "hedefimbelli" ascii //weight: 1
        $x_1_3 = "yenilmemezilmem.ravennaback" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLine_RDG_2147838224_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLine.RDG!MTB"
        threat_id = "2147838224"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "b112383d-4031-491c-9eab-8ec33c0038dd" ascii //weight: 1
        $x_1_2 = "version of CryptoObfuscator" wide //weight: 1
        $x_1_3 = "OpenProcess" ascii //weight: 1
        $x_1_4 = "GetCurrentProcessId" ascii //weight: 1
        $x_1_5 = "LoadLibrary" ascii //weight: 1
        $x_1_6 = "Socket" ascii //weight: 1
        $x_1_7 = "ThreadStart" ascii //weight: 1
        $x_1_8 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_RedLine_RDBH_2147844950_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/RedLine.RDBH!MTB"
        threat_id = "2147844950"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "72b4188a-1833-4378-92fa-1e3ba278f94b" ascii //weight: 1
        $x_1_2 = "SecurityHealthSystray" ascii //weight: 1
        $x_1_3 = "Updater Module" ascii //weight: 1
        $x_1_4 = "LyeM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

