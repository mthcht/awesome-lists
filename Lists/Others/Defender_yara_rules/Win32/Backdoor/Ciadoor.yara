rule Backdoor_Win32_Ciadoor_2147568555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ciadoor"
        threat_id = "2147568555"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ciadoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%EFLN" wide //weight: 1
        $x_1_2 = "%ESVA" wide //weight: 1
        $x_1_3 = "%BFLN" wide //weight: 1
        $x_1_4 = "%LsVA" wide //weight: 1
        $x_1_5 = "%BFLC" wide //weight: 1
        $x_1_6 = "%BEXE" wide //weight: 1
        $x_1_7 = "%EEXE" wide //weight: 1
        $x_1_8 = "%EMLT" wide //weight: 1
        $x_1_9 = "%BBOD" wide //weight: 1
        $x_1_10 = "%BMLT" wide //weight: 1
        $x_1_11 = "%EBOD" wide //weight: 1
        $x_1_12 = "%BBEG" wide //weight: 1
        $x_1_13 = "%EEND" wide //weight: 1
        $x_1_14 = "%BMST" wide //weight: 1
        $x_1_15 = "%EWLs" wide //weight: 1
        $x_1_16 = "%EMST" wide //weight: 1
        $x_1_17 = "%BWLs" wide //weight: 1
        $x_1_18 = "%BTIT" wide //weight: 1
        $x_1_19 = "%ETIT" wide //weight: 1
        $x_1_20 = "%EFLS" wide //weight: 1
        $x_1_21 = "%BFLS" wide //weight: 1
        $x_1_22 = "%EINJ" wide //weight: 1
        $x_1_23 = "%EFLC" wide //weight: 1
        $x_1_24 = "%BDLL" wide //weight: 1
        $x_1_25 = "%BINJ" wide //weight: 1
        $x_1_26 = "%EDLL" wide //weight: 1
        $x_1_27 = "%ESTF" wide //weight: 1
        $x_1_28 = "%LsTF" wide //weight: 1
        $x_1_29 = "%EBFS" wide //weight: 1
        $x_1_30 = "%BBFS" wide //weight: 1
        $x_1_31 = "hxnP@glb~a|raJ@qw~tknB\\USPFJQpBZZCDBqkW@]]AQGjuJVMHYO" wide //weight: 1
        $x_1_32 = "If Exist " wide //weight: 1
        $x_1_33 = " Goto Begin" wide //weight: 1
        $x_1_34 = "@Echo off" wide //weight: 1
        $x_1_35 = ":Begin" wide //weight: 1
        $x_5_36 = "nkoppl223a" wide //weight: 5
        $x_2_37 = "//UNBIND//" wide //weight: 2
        $x_1_38 = "explorer.exe" wide //weight: 1
        $x_1_39 = "DeclCin" ascii //weight: 1
        $x_1_40 = "ProgramFiles" wide //weight: 1
        $x_1_41 = "\\internet explorer\\iexplore.exe http://" wide //weight: 1
        $x_1_42 = "ThunderRT6FormDC" wide //weight: 1
        $x_3_43 = "*\\AC:\\ai\\l.vbp" wide //weight: 3
        $x_3_44 = "*\\AC:\\ui\\l.vbp" wide //weight: 3
        $x_1_45 = "\\del32.bat" wide //weight: 1
        $x_5_46 = " Objects\\{E14DCE67-8FB7-4721-8149-179BAA4D792C}" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((35 of ($x_1_*))) or
            ((1 of ($x_2_*) and 33 of ($x_1_*))) or
            ((1 of ($x_3_*) and 32 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 30 of ($x_1_*))) or
            ((2 of ($x_3_*) and 29 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 27 of ($x_1_*))) or
            ((1 of ($x_5_*) and 30 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 28 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 27 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 25 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 24 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 22 of ($x_1_*))) or
            ((2 of ($x_5_*) and 25 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 23 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 22 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 20 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 19 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 17 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Ciadoor_B_2147592534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ciadoor.gen!B"
        threat_id = "2147592534"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ciadoor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Active Setup\\Installed Components\\{44BBA855-CC51-11CF-AAFA-00AA00C7170S}" wide //weight: 10
        $x_5_2 = "CIA Notify" wide //weight: 5
        $x_1_3 = "%BBEG" wide //weight: 1
        $x_1_4 = "%EEND" wide //weight: 1
        $x_1_5 = "%BMPT" wide //weight: 1
        $x_1_6 = "%ETPT" wide //weight: 1
        $x_1_7 = "%BKPT" wide //weight: 1
        $x_1_8 = "%EKPT" wide //weight: 1
        $x_1_9 = "%BPAsL" wide //weight: 1
        $x_1_10 = "%EPAsL" wide //weight: 1
        $x_1_11 = "%BVIC" wide //weight: 1
        $x_1_12 = "%EVIC" wide //weight: 1
        $x_1_13 = "%BRGR" wide //weight: 1
        $x_1_14 = "%ERGR" wide //weight: 1
        $x_1_15 = "%BRGsL" wide //weight: 1
        $x_1_16 = "&port=" wide //weight: 1
        $x_1_17 = "&vicname=" wide //weight: 1
        $x_1_18 = "&usrname=" wide //weight: 1
        $x_1_19 = "&server=" wide //weight: 1
        $x_1_20 = "&password=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 16 of ($x_1_*))) or
            ((1 of ($x_10_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Ciadoor_C_2147792382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ciadoor.gen!C"
        threat_id = "2147792382"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ciadoor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {5a 68 10 c4 02 11 68 14 c4 02 11 52 e9 e7 ff ff ff}  //weight: 6, accuracy: High
        $x_1_2 = {78 78 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_2_3 = {1b 92 02 fb 30 1c 56 1f 00 1f f4 00 2b 56 fe f5 00 00 00 00 43 50 ff 04 50 ff f4 ff 2b 4e ff 0a}  //weight: 2, accuracy: High
        $x_2_4 = {1b d1 02 fb 30 1c 49 2b 00 24 f5 01 00 00 00 76 14 01 2e e0 fe 40 f4 07 fb fd fd c7 50 ff 7f 0c}  //weight: 2, accuracy: High
        $x_2_5 = {10 20 07 0a fe 2f 50 02 00 02 00 02 00 03 13 f8 04 c8 b4 ff 0b 80 01 00 00 19 68 ff 08 68 ff 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

