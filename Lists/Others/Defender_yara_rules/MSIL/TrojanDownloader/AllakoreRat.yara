rule TrojanDownloader_MSIL_AllakoreRat_CCHD_2147901510_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AllakoreRat.CCHD!MTB"
        threat_id = "2147901510"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AllakoreRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DisableTaskMgr" ascii //weight: 1
        $x_1_2 = "powershell -Command Add-MpPreference -ExclusionPath C:" ascii //weight: 1
        $x_1_3 = "drivers/etc/hosts" ascii //weight: 1
        $x_1_4 = "aHR0cDovL2lwaW5mby5pbw==" wide //weight: 1
        $x_1_5 = "TW96aWxsYS80LjAgKGNvbXBhdGlibGU7IE1TSUUgNi4wOyBXaW5kb3dzIE5UIDUuMjsgLk5FVCBDTFIgMS4wLjM3MDU7KQ==" wide //weight: 1
        $x_1_6 = "dXNlci1hZ2VudA==" wide //weight: 1
        $x_1_7 = "SGVhZGVycw==" wide //weight: 1
        $x_1_8 = "RWxhcHNlZCBtaWxpc2Vjb25kcyA9IA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

