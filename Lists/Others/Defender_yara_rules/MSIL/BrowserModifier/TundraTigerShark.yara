rule BrowserModifier_MSIL_TundraTigerShark_A_480936_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:MSIL/TundraTigerShark.A"
        threat_id = "480936"
        type = "BrowserModifier"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TundraTigerShark"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Google\\Chrome\\Application\\chrome.exe" ascii //weight: 1
        $x_1_2 = {4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 47 00 75 00 69 00 64 00 00 ?? 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 43 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 79 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "api.archiveentry.com" ascii //weight: 1
        $x_1_4 = "search.categoryresults.com" ascii //weight: 1
        $x_1_5 = "UPDATE keywords SET short_name='Google',url='{url}'" ascii //weight: 1
        $x_1_6 = "sync_guid = lower( hex(randomblob(4)) || '-' || hex(randomblob(2))" ascii //weight: 1
        $x_1_7 = {7b 00 22 00 43 00 61 00 6c 00 6c 00 22 00 3a 00 20 00 22 00 00 19 22 00 2c 00 20 00 22 00 55 00 73 00 65 00 72 00 22 00 3a 00 20 00 22 00 00 19 22 00 2c 00 20 00 22 00 53 00 65 00 73 00 68 00 22 00 3a 00 20 00 22 00 00 19 22 00 2c 00 20 00 22 00 49 00 4f 00 6e 00 65 00 22 00 3a 00 20 00 22 00 00 19 22 00 2c 00 20 00 22 00 49 00 54 00 77 00 6f 00 22 00 3a 00 20 00 22 00 00 2d 22 00 2c 00 20 00 22 00 41 00 64 00 64 00 69 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 49 00 6e 00 66 00 6f 00 22 00 3a 00 20 00 22 00 00 05 22 00 7d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

