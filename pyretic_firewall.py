# insert the name of the module and policy you want to import   
from pyretic.examples.pyretic_switch import act_like_switch   
from pyretic.examples.pyretic_hub import *   
#from mininet.topo import Topo   
import os   
import csv   
import string   
# if you want to edit csv   
from pyretic.modules.mac_learner import learn   
   
### FIREWALLS ###   
   
drop_ingress = if_(ingress_network(),drop)   
   
def poke(W,P):   
    p = parallel([match(srcip=s,dstip=d) for (s,d) in W])   
    return if_(p,passthrough,P)   
   
def static_fw(W):   
    W_rev = [(d,s) for (s,d) in W]   
    return poke(W_rev, poke(W, drop_ingress))   
   
   
#insert the name of the module and policy you want to import   
policy_file = "%s/pyretic/pyretic/examples/firewall-policies.csv" % os.environ[ 'HOME' ]   
   
def main():   
    # read firewall-policies.csv   
    csvfile = file(policy_file, 'rb')   
    reader = csv.reader(csvfile)   
    #start with a policy that doesn't match any packets   
    not_allowed=none   
   
   
    for line in reader:   
   
     if not(line[1]=='mac_0'):   
      #and add traffic that isn't allowed   
      not_allowed=not_allowed+(match(srcmac= MAC(line[1]),dstmac= MAC(line[2]))) + (match(srcmac= MAC(line[2]),dstmac= MAC(line[1])))   
   
    csvfile.close()   
    print not_allowed   
   
   
    # express allowed traffic in terms of not_allowed - hint use '~'.....   
    allowed=~not_allowed   
    print allowed   
   
    # and only send allowed traffic to the mac learning (act_like_switch) logic   
    return allowed>>act_like_switch()   
