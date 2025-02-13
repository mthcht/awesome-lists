rule Trojan_MSIL_FoxyBooks_B_2147812960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FoxyBooks.B!dha"
        threat_id = "2147812960"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FoxyBooks"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "5be98cc5-94e0-4aba-8c34-de2129337877" wide //weight: 10
        $x_5_2 = "setting.key" wide //weight: 5
        $x_5_3 = "987654!QA" wide //weight: 5
        $x_1_4 = "reziac@comcast.net" wide //weight: 1
        $x_1_5 = "pkilab@yahoo.com" wide //weight: 1
        $x_1_6 = "rhavyn@verizon.net" wide //weight: 1
        $x_1_7 = "dvdotnet@live.com" wide //weight: 1
        $x_1_8 = "codex@outlook.com" wide //weight: 1
        $x_1_9 = "matloff@optonline.net" wide //weight: 1
        $x_1_10 = "dsowsy@me.com" wide //weight: 1
        $x_1_11 = "iamcal@msn.com" wide //weight: 1
        $x_1_12 = "bmcmahon@outlook.com" wide //weight: 1
        $x_1_13 = "greear@yahoo.ca" wide //weight: 1
        $x_1_14 = "boein@hotmail.com" wide //weight: 1
        $x_1_15 = "imightb@hotmail.com" wide //weight: 1
        $x_1_16 = "mthurn@outlook.com" wide //weight: 1
        $x_1_17 = "kspiteri@optonline.net" wide //weight: 1
        $x_1_18 = "nwiger@hotmail.com" wide //weight: 1
        $x_1_19 = "chrisj@att.net" wide //weight: 1
        $x_1_20 = "nanop@yahoo.com" wide //weight: 1
        $x_1_21 = "boomzilla@gmail.com" wide //weight: 1
        $x_1_22 = "chaikin@att.net" wide //weight: 1
        $x_1_23 = "boein@verizon.net" wide //weight: 1
        $x_1_24 = "murty@icloud.com" wide //weight: 1
        $x_1_25 = "lcheng@yahoo.ca" wide //weight: 1
        $x_1_26 = "wmszeliga@me.com" wide //weight: 1
        $x_1_27 = "forsberg@me.com" wide //weight: 1
        $x_1_28 = "hyper@me.com" wide //weight: 1
        $x_1_29 = "ilikered@aol.com" wide //weight: 1
        $x_1_30 = "sabren@sbcglobal.net" wide //weight: 1
        $x_1_31 = "guialbu@hotmail.com" wide //weight: 1
        $x_1_32 = "north@sbcglobal.net" wide //weight: 1
        $x_1_33 = "sequin@comcast.net" wide //weight: 1
        $x_1_34 = "gospodin@hotmail.com" wide //weight: 1
        $x_1_35 = "granboul@mac.com" wide //weight: 1
        $x_1_36 = "daveewart@mac.com" wide //weight: 1
        $x_1_37 = "ntegrity@verizon.net" wide //weight: 1
        $x_1_38 = "nicktrig@aol.com" wide //weight: 1
        $x_1_39 = "sumdumass@comcast.net" wide //weight: 1
        $x_1_40 = "carcus@aol.com" wide //weight: 1
        $x_1_41 = "chlim@msn.com" wide //weight: 1
        $x_1_42 = "mirod@comcast.net" wide //weight: 1
        $x_1_43 = "wkrebs@yahoo.com" wide //weight: 1
        $x_1_44 = "chaki@icloud.com" wide //weight: 1
        $x_1_45 = "jfinke@att.net" wide //weight: 1
        $x_1_46 = "enintend@mac.com" wide //weight: 1
        $x_1_47 = "aschmitz@me.com" wide //weight: 1
        $x_1_48 = "karasik@outlook.com" wide //weight: 1
        $x_1_49 = "arathi@hotmail.com" wide //weight: 1
        $x_1_50 = "emmanuel@aol.com" wide //weight: 1
        $x_1_51 = "martyloo@att.net" wide //weight: 1
        $x_1_52 = "fukuchi@live.com" wide //weight: 1
        $x_1_53 = "juerd@msn.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

