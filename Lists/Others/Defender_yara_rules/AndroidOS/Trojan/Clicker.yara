rule Trojan_AndroidOS_Clicker_MF_2147744660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Clicker.MF!MTB"
        threat_id = "2147744660"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Clicker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.zyzy.gogo" ascii //weight: 2
        $x_1_2 = "&act=adv" ascii //weight: 1
        $x_1_3 = "aHR0cDovL2Fkc2NsdWJwYXJ0bmVycy5ydS9wLnBocA==" ascii //weight: 1
        $x_1_4 = "CHECK INET 2 END" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Clicker_B_2147779411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Clicker.B!MTB"
        threat_id = "2147779411"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Clicker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/iapp/app/logoActivity" ascii //weight: 2
        $x_1_2 = "yuv0.xml" ascii //weight: 1
        $x_1_3 = "/iApp/DownloadFileDir/TempDefaultDownFile" ascii //weight: 1
        $x_1_4 = "clicki" ascii //weight: 1
        $x_1_5 = "touchmonitor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Clicker_C_2147829436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Clicker.C!MTB"
        threat_id = "2147829436"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Clicker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/iapp/downloadfiledir/tempdefaultdownfile" ascii //weight: 1
        $x_1_2 = "clicki" ascii //weight: 1
        $x_1_3 = "lcom/iapp/app/logoactivity" ascii //weight: 1
        $x_1_4 = "touchmonitor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Clicker_E_2147833845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Clicker.E!MTB"
        threat_id = "2147833845"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Clicker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "adsclubpartners.ru/p.php" ascii //weight: 1
        $x_1_2 = "&act=adv" ascii //weight: 1
        $x_1_3 = "cpw.00xff.net/p.php" ascii //weight: 1
        $x_1_4 = "doInBackground" ascii //weight: 1
        $x_1_5 = "ADD_DEVICE_ADMIN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

