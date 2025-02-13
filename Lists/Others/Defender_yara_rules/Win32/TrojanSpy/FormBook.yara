rule TrojanSpy_Win32_FormBook_AR_2147750278_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/FormBook.AR!MTB"
        threat_id = "2147750278"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 1c 17 81 ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 31 f3 (3d|81) ?? ?? ?? ?? ?? (3d|81) [0-15] 11 1c 10 [0-15] 83 c2 04 (3d|81) ?? ?? ?? ?? ?? (3d|81) [0-10] 75}  //weight: 2, accuracy: Low
        $x_2_2 = "RHhvgnQ8BXErQ4ZymcOKbN2cxLj9B8O8v3nEB0WV2bc1qhq9VnDgua2TntAcUOViwuwR1I2X1505QiFwq3bWCkVaKNfjivf3ZT1i0VVSyzlMAwwlQ9" wide //weight: 2
        $x_1_3 = "QARvpB2DhtgFgAYDf5iuyT19qYNVZRDaepwclNslkPBpPqLkap4YJsXoutl7Q16SJ7KpWeoHFBYgmEFRNSCnpMSVT8" wide //weight: 1
        $x_1_4 = "WbTuM2tuEXpU1l05Mmn24159" wide //weight: 1
        $x_1_5 = "DVGVlF6VNafNy5eZJkiBK2afeCDrdfj3EmP55J385" wide //weight: 1
        $x_1_6 = {ff 34 0f 81 [0-63] 5b [0-47] 31 f3 [0-31] 81 ?? ?? ?? ?? ?? 89 1c 0a}  //weight: 1, accuracy: Low
        $x_1_7 = "ILaWz2ZJFwsWyD0LUqptbxv9wBdzUNOrv127" wide //weight: 1
        $x_2_8 = {11 1c 10 66 [0-15] 83 c2 04 [0-15] 81 fa ?? ?? 00 00 75 50 00 8b 1c 17}  //weight: 2, accuracy: Low
        $x_2_9 = {01 1c 10 66 [0-15] 83 c2 04 [0-10] 81 [0-31] 75 49 00 ff 34 17 [0-15] 5b [0-15] 31 f3}  //weight: 2, accuracy: Low
        $x_2_10 = {8b 1f 66 85 [0-31] 31 f3 [0-31] 89 1c 10 [0-1] 46 81 fa ?? ?? 00 00 75}  //weight: 2, accuracy: Low
        $x_1_11 = "fmcju3VP2q57" wide //weight: 1
        $x_1_12 = "Krykkenstinkadorosersumakker5" wide //weight: 1
        $x_2_13 = {ff 37 eb 03 00 02 34 ?? [0-10] 31 f1 00 02 89 0b 00 02 81 fa}  //weight: 2, accuracy: Low
        $x_1_14 = "ZeGXDMKRZTehn6Mm8V8WFPk3116" wide //weight: 1
        $x_1_15 = "XCZjOQiIMytr5usvctL68Rn6MbOPK1o6c8Sq8S248" wide //weight: 1
        $x_1_16 = {ff 37 85 c0 [0-47] 31 f1 [0-47] 01 d3 [0-47] 89 0b [0-47] 83 c2 04 [0-47] 81 fa ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_17 = "Xf9t3Akzd8X9lkKUX47n0LNd6QCG2kFqpF60" wide //weight: 1
        $x_1_18 = "blZGZfyl51mQ8rDKxcO2oIgZW6aj6tMzgpSMq40" wide //weight: 1
        $x_1_19 = {ff 37 81 fb [0-47] 31 f1 [0-47] 01 d3 [0-47] 89 0b [0-47] 83 c2 04 [0-47] 81 fa ?? b8 00}  //weight: 1, accuracy: Low
        $x_1_20 = "NluUvPr4buDgBBw9usxvo4ZvA7ajr7MSPXy4Z73" wide //weight: 1
        $x_1_21 = "uzQHzfibUgsgc4mTojhnuFAEtGTRD3vf50Xdv4ZA60" wide //weight: 1
        $x_1_22 = {ff 37 66 85 00 02 89 0b 00 02 83 c2 04 00 02 83 c7 04 00 02 31 f1 eb}  //weight: 1, accuracy: Low
        $x_1_23 = "YGvGXFa8o4TnON7NsjqwB9jPXukXn4j6Q246" wide //weight: 1
        $x_1_24 = "gl0Az56z3wiE0rz1zS76nx5yfzoD88" wide //weight: 1
        $x_1_25 = {ff 37 eb 0f 00 02 83 c2 04 00 02 89 0b 00 02 66 81 fa 00 02 31 f1 85}  //weight: 1, accuracy: Low
        $x_1_26 = "q1r0DE22eZPq2UmjblN1fNJyNUjm3ntnN6CdF223" wide //weight: 1
        $x_1_27 = "CjwZAhpeh1R87doqRo1kYSizg8pTDeGBdEhvDfa288" wide //weight: 1
        $x_1_28 = {ff 37 81 fa 00 05 31 f1 00 05 09 0b 00 05 66 3d 00 05 66 85 d2 [0-10] e9}  //weight: 1, accuracy: Low
        $x_1_29 = "SCdtjRerAMs5YXddAjNM90MU79" wide //weight: 1
        $x_1_30 = "i5YNpYZ23b8ucqCDg1Omn4INXWvpoZvk9qgUWE2A207" wide //weight: 1
        $x_1_31 = {01 0b eb 1b ef 00 8b 09 00 02 31 f1}  //weight: 1, accuracy: Low
        $x_1_32 = "C8dgDBlrF5n4MUG8VNl189" wide //weight: 1
        $x_1_33 = "KEYstore" wide //weight: 1
        $x_1_34 = {31 4b 00 a0 [0-31] 00 12 31 4b 00 [0-31] 00 41 36 [0-1] 46 4b 00 0c 36}  //weight: 1, accuracy: Low
        $x_1_35 = "fvqRWXQEnoYAmwWenDyoCWNjsBSLGSmGdrGrbngDbonmmUGsUG" wide //weight: 1
        $x_1_36 = "koxvzuiczqeidssoinjzupjkuhiiqur" wide //weight: 1
        $x_1_37 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS\\RESU_TNERRUC_YEKH" wide //weight: 1
        $x_1_38 = "\\dnammoc\\nepo\\llehs\\PTTH\\TOOR_SESSALC_YEKH" wide //weight: 1
        $x_1_39 = {32 40 00 04 00 00 00 d5 c5 46 00 dc c5 46 00 eb}  //weight: 1, accuracy: High
        $x_1_40 = "CRPEZDMMQKUVGYZOOGSPGJIJH" wide //weight: 1
        $x_1_41 = "ruqiihukjpuzjniossdieqzciuzvxok" wide //weight: 1
        $x_1_42 = "W8EfN4E5Ptdmuiz4jfDiBJicpXYlGlu6L94y7o112" wide //weight: 1
        $x_1_43 = "OPwomkMwnfirCWkkeq4GCawAlVDhu5E07YQ33" ascii //weight: 1
        $x_1_44 = "EwyEfuybiDtBD2nRh5nB4WlkjeJGRXM5jNQ240" wide //weight: 1
        $x_1_45 = "M6C0G3US494fFvSBya7m6od49S10wyVQFm6238" wide //weight: 1
        $x_1_46 = "j5sswMDqp1oS61uB5O3k14p2FZkCfuhCUIbnvH121" wide //weight: 1
        $x_1_47 = "eWTh5HSLyR7eTQjmEpmf3areJyiOEWT2m38106" wide //weight: 1
        $x_1_48 = {02 ca 31 34 24 0f ee ca 0f da ca 59 0f 38 02 ca 0f ee ca 89 0c 18}  //weight: 1, accuracy: High
        $x_1_49 = "pmaEFGcSicN0v24VIK2YVfsba95yte9MRc03I54" wide //weight: 1
        $x_1_50 = "J8egKhEM1a1JgihiOe0Onnfc5YIsHb4xcHIowhyl253" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

