rule Backdoor_Java_Frurat_A_2147679302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Java/Frurat.A"
        threat_id = "2147679302"
        type = "Backdoor"
        platform = "Java: Java binaries (classes)"
        family = "Frurat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {63 6f 6e 65 78 69 6f 6e [0-16] 6a 61 76 61 2f 6e 65 74 2f 53 6f 63 6b 65 74}  //weight: 5, accuracy: Low
        $x_5_2 = {6f 70 63 69 6f 6e 65 73 2f 4f 70 63 69 6f 6e [0-16] 66 69 6c 65}  //weight: 5, accuracy: Low
        $x_5_3 = {70 75 65 72 74 6f [0-16] 70 75 65 72 74 6f [0-16] 70 61 73 73 [0-16] 74 69 6d 65}  //weight: 5, accuracy: Low
        $x_1_4 = "urldownload" ascii //weight: 1
        $x_1_5 = "getPassword" ascii //weight: 1
        $x_1_6 = "Valor de comando:" ascii //weight: 1
        $x_1_7 = {70 6c 75 67 69 6e 4c 6f 63 61 6c [0-16] 75 72 6c [0-16] 75 72 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Java_Frurat_A_2147679302_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Java/Frurat.A"
        threat_id = "2147679302"
        type = "Backdoor"
        platform = "Java: Java binaries (classes)"
        family = "Frurat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "getResourceAsStream" ascii //weight: 2
        $x_2_2 = "getSystemLookAndFeelClassName" ascii //weight: 2
        $x_2_3 = {70 61 73 73 [0-16] 70 6f 72 74 [0-16] 70 6f 72 74}  //weight: 2, accuracy: Low
        $x_1_4 = "frautas" ascii //weight: 1
        $x_1_5 = "config." ascii //weight: 1
        $x_1_6 = "WindowsStartupService" ascii //weight: 1
        $x_1_7 = "addShutdownHook" ascii //weight: 1
        $x_10_8 = {74 6d 70 64 69 72 [0-16] 66 72 61 75 74 61 73 2e 6c 6f 63 6b}  //weight: 10, accuracy: Low
        $x_10_9 = "frutasrat." ascii //weight: 10
        $x_10_10 = {68 6f 73 74 [0-16] 70 61 73 73 [0-16] 70 6f 72 74 [0-16] 70 6f 72 74 [0-16] 74 65 6d 70}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Java_Frurat_A_2147679302_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Java/Frurat.A"
        threat_id = "2147679302"
        type = "Backdoor"
        platform = "Java: Java binaries (classes)"
        family = "Frurat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "java/util/logging/Logger" ascii //weight: 5
        $x_5_2 = "java/io/File" ascii //weight: 5
        $x_5_3 = "extra/RegistryUtils" ascii //weight: 5
        $x_5_4 = {44 65 73 69 6e 73 74 61 6c 61 [0-16] 72 75 74 61}  //weight: 5, accuracy: Low
        $x_5_5 = {72 75 74 61 [0-16] 4c 6a 61 76 61 2f 6c 61 6e 67 2f 53 74 72 69 6e 67 [0-16] 72 65 67 69 73 74 72 6f}  //weight: 5, accuracy: Low
        $x_1_6 = "getResourceAsStream" ascii //weight: 1
        $x_1_7 = "getRuntime" ascii //weight: 1
        $x_1_8 = "getLogger" ascii //weight: 1
        $x_1_9 = "schtasks" ascii //weight: 1
        $x_1_10 = "/delete" ascii //weight: 1
        $x_1_11 = "registroKey" ascii //weight: 1
        $x_1_12 = "Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 7 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

