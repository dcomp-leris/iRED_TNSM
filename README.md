# iRED
ingress Random Early Detection - P4

# Definition
iRED is a disaggregated P4-AQM fully implemented in programmable data plane hardware (Tofino2) and L4S capable. iRED splits the AQM logic into two parts: the decision and the action. The decision part, which depends on the queuing delay metadata, is deployed in the Egress block. The action part, which is responsible for dropping the packet, is deployed in the Ingress block. Additionally, it accomplishes this by categorizing traffic as either Classic (subject to dropping) or Scalable (marked with the ECN bit, thus ensuring fairness among various flows through a combined packet dropping and marking mechanism.

# Design of iRED
![alt-text](https://github.com/leandrocalmeida/iRED-T2NA/blob/main/figs/iRED.jpg)

# Folders
