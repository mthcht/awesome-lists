rule Trojan_MSIL_GravityRat_K_2147769686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GravityRat.K!MTB"
        threat_id = "2147769686"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GravityRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetAV" ascii //weight: 1
        $x_1_2 = "get_Macid" ascii //weight: 1
        $x_1_3 = "get_Cpuid" ascii //weight: 1
        $x_1_4 = "get_MachineName" ascii //weight: 1
        $x_1_5 = "get_FullName" ascii //weight: 1
        $x_1_6 = "get_UserDomainName" ascii //weight: 1
        $x_1_7 = "get_UserName" ascii //weight: 1
        $x_1_8 = "get_Pcname" ascii //weight: 1
        $x_1_9 = "get_Osversion" ascii //weight: 1
        $x_1_10 = "get_AntiVInfo" ascii //weight: 1
        $x_1_11 = "GetWebRequest" ascii //weight: 1
        $x_5_12 = "setuserinfo.php" wide //weight: 5
        $x_5_13 = "updateantivirusinfo.php" wide //weight: 5
        $x_5_14 = "setlastseen.php" wide //weight: 5
        $x_5_15 = "downloads.php" wide //weight: 5
        $x_5_16 = "setupdated.php" wide //weight: 5
        $x_5_17 = "SELECT * FROM AntiVirusProduct" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

