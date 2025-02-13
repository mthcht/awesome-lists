rule Trojan_MacOS_Yontoo_A_2147745045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Yontoo.A"
        threat_id = "2147745045"
        type = "Trojan"
        platform = "MacOS: "
        family = "Yontoo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "data.downloadstarter.net/pingmac.asp" ascii //weight: 1
        $x_1_2 = "/Contents/Resources/SportHunterTVApp.app" ascii //weight: 1
        $x_1_3 = "/private/var/tmp/YontooMacSilentInstaller" ascii //weight: 1
        $x_1_4 = "/Applications/Yontoo Installer Silent.app/Contents/MacOS/Yontoo" ascii //weight: 1
        $x_1_5 = "www.yontoo.com/PrivacyPolicy.aspx" ascii //weight: 1
        $x_2_6 = {ff 15 38 60 02 00 48 31 8d 35 41 60 02 00 4c 89 e7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

