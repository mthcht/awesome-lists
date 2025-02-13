rule Trojan_AndroidOS_FakeNeflick_A_2147650492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeNeflick.A"
        threat_id = "2147650492"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeNeflick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "erofolio.no-ip.biz/login.php" ascii //weight: 1
        $x_1_2 = "Your Android TV is not supported" ascii //weight: 1
        $x_1_3 = "netflix_bkg" ascii //weight: 1
        $x_1_4 = "webServerAnswer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

