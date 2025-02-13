rule Trojan_AndroidOS_XLoader_B_2147787638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/XLoader.B"
        threat_id = "2147787638"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "XLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "c2V0Q29tcG9uZW50RW5hYmxlZFNldHRpbmc=" ascii //weight: 1
        $x_1_2 = ".Loader" ascii //weight: 1
        $x_2_3 = {07 00 22 00 [0-12] 70 10 ?? ?? 00 00 6e 10 ?? ?? 07 00 0c 01 [0-10] 6e 10 ?? ?? 01 00 0c 01 [0-10] 6e 20 ?? ?? 10 00 62 01 [0-12] 6e 20 ?? ?? 10 00 1a 01 [0-12] 6e 20 ?? ?? 10 00 6e 10 ?? ?? 00 00 0c 00 [0-10] 22 01 [0-12] 70 20 ?? ?? 01 00 6e 10 ?? ?? 01 00 0a 00 [0-10] 38 00 [0-12] 6e 10 ?? ?? 01 00 22 00 [0-12] 70 10 ?? ?? 00 00 6e 10 ?? ?? 07 00 0c 02 [0-10] 1a 03 [0-12] ?? ?? ?? ?? 32 00 0c 02 [0-10] 16 03 04 00 [0-10] 6e 30 ?? ?? 32 04 22 03 [0-12] 70 20 ?? ?? 23 00 13 02 00 08 [0-10] 23 22 [0-12] 6e 20 ?? ?? 23 00 0a 04 [0-10] 12 f5 [0-10] 12 06 [0-228] 00 00 6e 10 ?? ?? 01 00 0c 00 [0-10] 70 20 ?? ?? 07 00 0e 00 [0-10] 6e 40 ?? ?? 20 46}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_XLoader_BA_2147795424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/XLoader.BA"
        threat_id = "2147795424"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "XLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c2V0Q29tcG9uZW50RW5hYmxlZFNldHRpbmc=" ascii //weight: 1
        $x_1_2 = "METASPLOIT" ascii //weight: 1
        $x_1_3 = ".Loader" ascii //weight: 1
        $x_1_4 = "android.intent.action.BOOT_COMPLETED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

