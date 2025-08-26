rule Trojan_Linux_MemCodeExec_SR13_2147950250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MemCodeExec.SR13"
        threat_id = "2147950250"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MemCodeExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[data|bss|stack|stack-exec|malloc-rw|malloc-rw-x|mmap-rw|mmap-rwx|" ascii //weight: 1
        $x_1_2 = "|mmap-rw-x|shm-open-rwx|shmget-rw|shmget-rwx|shmget-rw-x]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

