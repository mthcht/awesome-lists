rule TrojanDownloader_Win32_Zibest_A_2147575544_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zibest.gen!A"
        threat_id = "2147575544"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zibest"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://traffnew.biz/progs/" ascii //weight: 2
        $x_2_2 = "http://traffnew.biz/dl/" ascii //weight: 2
        $x_2_3 = ":$:*:1:::B:I:T:Z:`:j:p:v:" ascii //weight: 2
        $x_2_4 = "=H=R=a=k=x=" ascii //weight: 2
        $x_2_5 = "=/=;=A=g=o=" ascii //weight: 2
        $x_2_6 = "dluniq1.php?exp=2&adv=adv682&code1=HNNE&code2=5121" ascii //weight: 2
        $x_2_7 = "F-Secure Gatekeeper Handler Starter" ascii //weight: 2
        $x_2_8 = "BackWeb Plug-in - 4476822" ascii //weight: 2
        $x_2_9 = "dluniq1.php?exp=2&adv=" ascii //weight: 2
        $x_2_10 = "traffnew.biz" ascii //weight: 2
        $x_2_11 = "pccguide.exe" ascii //weight: 2
        $x_2_12 = "fsguidll.exe" ascii //weight: 2
        $x_2_13 = "SharedAccess" ascii //weight: 2
        $x_2_14 = "fsgk32st.exe" ascii //weight: 2
        $x_2_15 = "secure32.php" ascii //weight: 2
        $x_2_16 = "PcCtlCom.exe" ascii //weight: 2
        $x_2_17 = "\\toolbar.exe" ascii //weight: 2
        $x_2_18 = "\\paytime.exe" ascii //weight: 2
        $x_2_19 = "\\tool5.exe" ascii //weight: 2
        $x_2_20 = "fsdfwd.exe" ascii //weight: 2
        $x_2_21 = "\\tool4.exe" ascii //weight: 2
        $x_2_22 = "fsgk32.exe" ascii //weight: 2
        $x_2_23 = "fssm32.exe" ascii //weight: 2
        $x_2_24 = "FSAV32.exe" ascii //weight: 2
        $x_10_25 = {8d 7d f8 83 c9 ff 33 c0 88 5d fc f2 ae f7 d1 2b f9 8d 95 b4 fb ff ff 8b f7}  //weight: 10, accuracy: High
        $x_10_26 = {80 3e 22 75 0d 46 eb 0a 3c 20 7e 06 46 80 3e 20 7f fa 8a 06 84 c0 74 04 3c 20 7e e9}  //weight: 10, accuracy: High
        $x_5_27 = {c6 45 84 26 c6 45 85 63 c6 45 86 6f c6 45 87 64 c6 45 88 65 c6 45 89 32 c6 45 8a 3d 88 5d 8b}  //weight: 5, accuracy: High
        $x_5_28 = {c6 85 64 fd ff ff 53 c6 85 65 fd ff ff 68 c6 85 66 fd ff ff 61 c6 85 67 fd ff ff 72 c6 85 68 fd ff ff 65}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((18 of ($x_2_*))) or
            ((1 of ($x_5_*) and 15 of ($x_2_*))) or
            ((2 of ($x_5_*) and 13 of ($x_2_*))) or
            ((1 of ($x_10_*) and 13 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 10 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 8 of ($x_2_*))) or
            ((2 of ($x_10_*) and 8 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

