rule Backdoor_AndroidOS_SpamBot_A_2147811436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/SpamBot.A!xp"
        threat_id = "2147811436"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "SpamBot"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "://192.225.226.114:8080/SmsWeb/AddSms" ascii //weight: 2
        $x_1_2 = {63 6f 6d 2f [0-21] 4c 61 75 6e 63 68 65 72 24 57 65 61 6b 48 61 6e 64 6c 65 72 24 31}  //weight: 1, accuracy: Low
        $x_1_3 = "Lcom/squareup/okhttp/internal/DiskLruCache$Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

