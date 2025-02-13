rule Trojan_MSIL_RealProtect_CM_2147838430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RealProtect.CM!MTB"
        threat_id = "2147838430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RealProtect"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovL2lwaW5mby5pbw==" ascii //weight: 1
        $x_1_2 = "dXNlci1hZ2VudA==" ascii //weight: 1
        $x_1_3 = "TW96aWxsYS80LjAgKGNvbXBhdGlibGU7IE1TSUUgNi4wOyBXaW5kb3dzIE5UIDUuMjsgLk5FVCBDTFIgMS4wLjM3MDU7KQ==" ascii //weight: 1
        $x_1_4 = "XG1lemE=" ascii //weight: 1
        $x_1_5 = "HP.exe" ascii //weight: 1
        $x_1_6 = "127.0.0.1 elsj.banorte.com" ascii //weight: 1
        $x_1_7 = "powershell -Command Add-MpPreference -ExclusionPath C:" ascii //weight: 1
        $x_1_8 = "drivers/etc/hosts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

