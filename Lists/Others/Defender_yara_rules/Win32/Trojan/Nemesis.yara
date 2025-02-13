rule Trojan_Win32_Nemesis_RB_2147827410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nemesis.RB!MTB"
        threat_id = "2147827410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemesis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Surmlkens.Alb" ascii //weight: 1
        $x_1_2 = "Samfundsansvar.lnk" ascii //weight: 1
        $x_1_3 = "Dreidels.Sta" ascii //weight: 1
        $x_1_4 = "Coenobite.dll" ascii //weight: 1
        $x_1_5 = "Undersoegelse.Kun" ascii //weight: 1
        $x_1_6 = "Software\\Refleksfries\\Outlot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nemesis_RC_2147827794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nemesis.RC!MTB"
        threat_id = "2147827794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemesis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encurtain levnedsmiddellovene Clemmensen" ascii //weight: 1
        $x_1_2 = "Adgangsrettighederne" ascii //weight: 1
        $x_1_3 = "Sachsen-Anhalt" ascii //weight: 1
        $x_1_4 = "Systemstart Atomspaltningen Kabinepersonaler" wide //weight: 1
        $x_1_5 = "Saltsyres falstringer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nemesis_RD_2147827800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nemesis.RD!MTB"
        threat_id = "2147827800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemesis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sandusky afsonende" wide //weight: 1
        $x_1_2 = "Incrept Roosted PAMPERED" wide //weight: 1
        $x_1_3 = "Imaginations Plantningernes" wide //weight: 1
        $x_1_4 = "GetShortPathNameA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

