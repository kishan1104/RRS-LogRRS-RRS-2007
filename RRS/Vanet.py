import RRS_Vanet

class Vehicle():
    def __init__(self,network:object):
        self.network = network                             #initilizing the network object
        self.pk,self.__sk = RRS_Vanet.generate_publickey() #generating key pairs for the current vehicle
        self.network.join(self.pk)                         #vehicle automatically joins the network

    def leave_network(self,pk):
        self.network.leave(pk)                             #vehicle leaving the network
        
    def Send_message(self,message):
        pi = self.network.Y.index(self.pk)                 #get the list of vehicles in the network and get index of our vehicle
        signature = self.network.RRS.sign(self.__sk,pi,message) # Sign the message using RRS scheme to achieve anonymity 
        self.network.updateMsg(message,signature)               # Send the message to the network

    def checkMessages(self):
        if len(self.network.m_list)<1:                          # check if any messages are present 
            print("no messages to display")
        for i  in self.network.m_list:
            print(i[0])                                         # print all the messages broadcasted in the network



class Network():
    def __init__(self):
        self._vehicles = []                                     # initialze the vehicles in the network
        self.pk,self.__sk = RRS_Vanet.generate_publickey()      # generate admin public and private keys
        self._m_list = []                                       # the messages and signatures list maintained my the network
        self.rrs = RRS_Vanet.RRS('Network1',len(self._vehicles),self._vehicles,self.pk)  #initialize the rrs object 
    
    def join(self,pk):                                          # function to add the pk to the network
        self.Y.append(pk)
        self.updateObj()                                        # update the rrs object

    def leave(self,pk):                                         # function to remove the pk from the network
        self.Y.pop(self.Y.index(pk))
        self.updateObj()                                        # update the rrs object

    def updateObj(self):                                        # function to update the rrs object
        self.rrs = RRS_Vanet.RRS('Network1',len(self.Y),self.Y,self.pk)
    
    @property                                                   # read only access to the publickeys
    def Y(self):
        return self._vehicles
    
    @property                                                   # read only access to the message list
    def m_list(self):
        return self._m_list
    @property
    def RRS(self):                                              # read only acces to the rrs object
        return self.rrs
    
    def updateMsg(self,msg,signature):                           
        if self.rrs.vrfy(signature,msg):                        # check if the message signature pair is valid 
            self._m_list.append([msg,signature])                # if valid update the message list
        else:
            raise ValueError("invalid signature for the message") # else raise the error
    
    def revoke_user(self,signature,M):                          # revoke the user
        pk = self.rrs.revoke(signature,self.__sk,M)             # get the pubic key of the signer
        self._m_list.pop(self._m_list.index([M,signature]))     # remove the malicious message from the broadcast
        self._vehicles.pop(self._vehicles.index(pk))            # remove the malicious user from the network
        print("revoked user successfully")


if __name__=='__main__':
    net = Network()
    veh1 = Vehicle(net)
    veh2 = Vehicle(net)
    veh3 = Vehicle(net)
    veh4 = Vehicle(net)

    veh1.Send_message("Hello this is vehicle 1")
    veh3.Send_message("this is vehicle 3")
    # net.revoke_user(net.m_list[0][1],net.m_list[0][0])

    veh4.checkMessages()