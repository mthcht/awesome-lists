rule PWS_Win32_Hoardy_2147744303_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Hoardy!dha"
        threat_id = "2147744303"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Hoardy"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://%s/trustedr.aspx?version=%s" ascii //weight: 1
        $x_1_2 = "http://%s/provider.aspx?cf=%s" ascii //weight: 1
        $x_1_3 = "http://%s/feeyo.aspx?cc=%s" ascii //weight: 1
        $x_1_4 = "http://%s/topic.aspx?h=%s" ascii //weight: 1
        $x_1_5 = "http://%s/thumbnail.aspx?cfr=%s" ascii //weight: 1
        $x_1_6 = "shfam9y/ebuy.aspx" wide //weight: 1
        $x_1_7 = "shfam9y/amazon.aspx" wide //weight: 1
        $x_1_8 = "shfam9y/people.aspx" wide //weight: 1
        $x_1_9 = "shfam9y/Direct9.aspx" wide //weight: 1
        $x_1_10 = "DisableCMD" wide //weight: 1
        $x_1_11 = "p3oahin/pratty.aspx" wide //weight: 1
        $x_1_12 = "p3oahin/tiebak.aspx" wide //weight: 1
        $x_1_13 = "p3oahin/ugctag.aspx" wide //weight: 1
        $x_1_14 = "p3oahin/verycd.aspx" wide //weight: 1
        $x_1_15 = "p3oahin/worldcat.aspx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

