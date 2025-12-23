rule Ransom_Linux_BQTLock_A_2147959950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/BQTLock.A!MTB"
        threat_id = "2147959950"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "BQTLock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BQTLockClient" ascii //weight: 1
        $x_1_2 = "rm -rf /mnt/backups/*" ascii //weight: 1
        $x_1_3 = "/tmp/bqt_log.txt" ascii //weight: 1
        $x_1_4 = "encrypted_count" ascii //weight: 1
        $x_1_5 = "btrfs subvolume delete /snapshots/*" ascii //weight: 1
        $x_1_6 = "zfs destroy -r -f pool/snapshots" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

