rule Trojan_Win32_Klovbot_D_2147651585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Klovbot.D"
        threat_id = "2147651585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Klovbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 3a 00 5c 00 52 00 4f 00 42 00 45 00 52 00 54 00 4f 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "server=ROBINSON;uid=ROBINSON;pwd=ROBINSON;database=ROBINSON" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Klovbot_J_2147656086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Klovbot.J"
        threat_id = "2147656086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Klovbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\vOlk-Botnet" wide //weight: 1
        $x_1_2 = "2F70726976382F" wide //weight: 1
        $x_1_3 = "536F6674776172655C4D6963726F736F66745C57696E646F77735C43757272656E7456657273696F6E5C52756E" wide //weight: 1
        $x_1_4 = "Microsoft_WinInet_" wide //weight: 1
        $x_1_5 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" wide //weight: 1
        $x_1_6 = "bots.php" wide //weight: 1
        $x_1_7 = "QfH205c3Msk2+mAVLjb6Tgb6S4" wide //weight: 1
        $x_1_8 = "2653544C667470733D" wide //weight: 1
        $x_1_9 = "2653544C6D61696C733D" wide //weight: 1
        $x_1_10 = "2653544C696537383D" wide //weight: 1
        $x_1_11 = "5C73797374656D33325C647269766572735C6574635C686F737473" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

