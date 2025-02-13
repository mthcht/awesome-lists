rule Trojan_AndroidOS_DroidKrungFu_A_2147646402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/DroidKrungFu.A"
        threat_id = "2147646402"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "DroidKrungFu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 0b 63 70 4c 65 67 61 63 79 52 65 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 63 6f 6d 3a 38 35 31 31 2f 73 65 61 72 63 68 2f 73 61 79 68 69 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 72 61 74 63 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_DroidKrungFu_B_2147647141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/DroidKrungFu.B"
        threat_id = "2147647141"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "DroidKrungFu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/system/bin/chmod 755 /system/bin/busybox" ascii //weight: 1
        $x_1_2 = "/WebView.db" ascii //weight: 1
        $x_1_3 = "/system/etc/.rild_cfg" ascii //weight: 1
        $x_1_4 = "/secbino" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_DroidKrungFu_C_2147650000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/DroidKrungFu.C"
        threat_id = "2147650000"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "DroidKrungFu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.noshufou.android.su" ascii //weight: 1
        $x_1_2 = "CPInstFail" ascii //weight: 1
        $x_1_3 = "YPEdsada" ascii //weight: 1
        $x_1_4 = "DownFailed" ascii //weight: 1
        $x_1_5 = "newrpt.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_DroidKrungFu_D_2147650662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/DroidKrungFu.D"
        threat_id = "2147650662"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "DroidKrungFu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "execSysInstall" ascii //weight: 1
        $x_1_2 = "lilhermitCore" ascii //weight: 1
        $x_1_3 = "execUpBin" ascii //weight: 1
        $x_1_4 = "DIALOG_GRANT_SU" ascii //weight: 1
        $x_1_5 = "tryInstBin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_DroidKrungFu_E_2147655629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/DroidKrungFu.E"
        threat_id = "2147655629"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "DroidKrungFu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ad.gongfu-android.com:7500/ad/nweb.php?" ascii //weight: 1
        $x_1_2 = "com.noshufou.android.su" ascii //weight: 1
        $x_1_3 = {6e 61 64 70 2e 70 68 70 3f 76 3d [0-3] 26 69 64 3d 61 6c 6c}  //weight: 1, accuracy: Low
        $x_1_4 = "atools/battery" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_DroidKrungFu_F_2147656121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/DroidKrungFu.F"
        threat_id = "2147656121"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "DroidKrungFu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 6c 6f 67 6f ?? ?? 6d 79 6c 6f 67 6f 2e 6a 70 67 ?? ?? 2f 73 79 73 74 65 6d 2f 62 69 6e 2f 63 68 6d 6f 64}  //weight: 1, accuracy: Low
        $x_1_2 = "system/xbin/chmod 0755" ascii //weight: 1
        $x_1_3 = "UpdateCheck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_DroidKrungFu_H_2147658238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/DroidKrungFu.H"
        threat_id = "2147658238"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "DroidKrungFu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&lan=zh&country=CN&network=" ascii //weight: 1
        $x_1_2 = {26 70 61 64 3d 30 26 6d 61 3d 32 2e 33 2e ?? 2c 41 6e 64 72 6f 69 64 25 32 30}  //weight: 1, accuracy: Low
        $x_2_3 = "ad.gongfu-android.com:7500/ad" ascii //weight: 2
        $x_2_4 = "dd.phonego8.com:7500/ad" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_DroidKrungFu_I_2147658239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/DroidKrungFu.I"
        threat_id = "2147658239"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "DroidKrungFu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/UpdateCheck$1;" ascii //weight: 1
        $x_1_2 = "UpdateCheck.java" ascii //weight: 1
        $x_1_3 = {61 63 63 65 73 73 24 30 ?? ?? 61 63 63 65 73 73 24 31}  //weight: 1, accuracy: Low
        $x_1_4 = {6c 6f 61 64 4c 69 62 72 61 72 79 ?? ?? 6d 43 68 ?? ?? 6d 49 64}  //weight: 1, accuracy: Low
        $x_1_5 = {6d 65 74 61 44 61 74 61 ?? ?? 4d 59 41 44 5f 50 49 44}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

