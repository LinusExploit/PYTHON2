#!/usr/bin/python2

from bigdata import generictask


class UserTask (generictask.GenericTask):
    
    def object_finder (self, acl_name, show_run, offset):

        #raw_input('test1')
        
        inside_acl = False
        obj_o = None
        acl_o = None
        c = 0
        F = 'ip access-list extended '+ acl_name
        
        #print "F =" , F
        #print len(F)
        #print (F == 'ip access-list extended XXXXX_IPSEC_ACL')
        for line in show_run:
            #print line
            #print len(line)
            #raw_input('test2')
            
            
            
            
            #print 'found an access-list'
            #print F== line
            if F == line.strip():
                #print "evaluating"
                inside_acl = True
                #print 'case 1'
                #print c
				#print 'fuck'
                acl_o = c + offset
                c = c + 1
                continue
            
            if ('object-group' in line) and (inside_acl == True) :
                #print 'match found ' + acl_name
                #print 'True'
                inside_acl = False
                #print 'case 2'
                obj_o = c + offset
                
                return {'found': True, 'acl_o': acl_o, 'obj_o': obj_o}
                
            
            #print c 
            if ('ip access-list extende' in line) and inside_acl == True:
                #print 'case 3'
                inside_acl = False
                c = c + 1
                continue
            c = c + 1
                
        return {'found': False, 'acl_o': None, 'obj_o': None}


    def action(self, parsed_file):
        """
        This is a BORG signature for IOS Show Tech Parser. 
        
        This is a Borg signature to detect if we are using an object group inside an acesss lis that is used with a crypto map on IOS routers .
   
        """

        

        results_to_return = []
        multiple_line_values = []
        debugs = []


        show_run = parsed_file.get_command('show running-config')['lines']
        offset = parsed_file.get_command('show running-config')['offset']
        

        
        inside_map = False
        offset_map = None
        name_acl = None
            
        for indice,line in enumerate (show_run):
            
            if 'crypto map' in line :
                inside_map = True
                offset_map = indice + offset 
                
            if 'match address' in line and inside_map == True:
                name_acl = line.split()[2]
                debugs.append("test")
                call = self.object_finder(name_acl, show_run, offset)
                if call['found'] == True:
                    multiple_line_values.extend( [{'start':offset_map, 'end':offset_map}, {'start':indice+offset, 'end':indice + offset},{'start': call['acl_o'], 'end': call['acl_o']}, {'start': call['obj_o'], 'end': call['obj_o']}])
                    
                    results = {'severity':  'error' ,
                     'title':  'Crypto map references ACL with object-group, which could cause all traffic to be encrypted.',
                      'text':  '''An object group has been used with the following access list: %s.
                      This is not  supported feature on IOS, it causes the object to be replaced with any in the actual access-list.
                      Please consider attaching your service request to the following defect:
                      <a href="http://wwwin-metrics.cisco.com/cgi-bin/ddtsdisp.cgi?id=CSCsq33560"  target="_blank">CSCsq33560    ENH: Add support for object group ACL in ipsec crypto ACL on IOS  .</a></h3>
                  ''' % name_acl,
                     'external_title':'Using object groups is not supported with crypto access lists.',
                     'external_text':'',
                  
                     'multiple_line_values':    multiple_line_values}
                    results_to_return.append(results)
            
        #if not multiple_line_values: results_to_return = []

        self.out (results_to_return, name='result', type='list')
        self.out (debugs, type='list', name='debugs')


if __name__ == '__main__':
    '''
    This is run when the task is launched from command line.
    Give json inputs in stdin or in a file with --input file.json
    '''
    from bigdata.utility import pretty_print
    from bigdata.utility import json_input
    task = UserTask(json_input())
    result = task.run()