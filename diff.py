#!/usr/bin/python3
import sys

COL = {
    'CLEAR' : '\033[0m',
    'BLACK' : '\033[30m',
    'RED'   : '\033[91m',
    'GREEN' : '\033[92m',
    'YELLOW': '\033[93m',
    'BLUE'  : '\033[34m',
    'PURPLE': '\033[35m',
    'CYAN'  : '\033[36m',
    'WHITE' : '\033[37m'
}

class Node:
    def __init__(self,mi,ni,d,parent,dparent,dir):
        self.mi = mi
        self.ni = ni
        self.d = d
        self.parent = parent
        self.dparent = dparent
        self.dir = dir

    def __repr__(self):
        return '('+str(self.mi)+','+str(self.ni)+','+self.dir+')'

def snake(arr_m, arr_n, comp, node):
    m = node.mi
    n = node.ni
    ret = node
    while m < len(arr_m)-1 and n < len(arr_n)-1 and comp(arr_m[m+1],arr_n[n+1]):
        tmp = Node(m+1,n+1,node.d,ret,node,'s')
        ret = tmp
        m += 1
        n += 1
    return ret

def diff(arr1, arr2, comp, result_func):
    dict_map = {}
    m = arr1
    n = arr2
    ds = []
    first = snake(m,n,comp,Node(-1,-1,0,None,None,''))
    ds.append( {(first.mi,first.ni):first} )
    dict_map[(first.mi,first.ni)] = True

    result = Node(0,0,0,None,None,'')
    
    if first.mi >= len(m)-1 and first.ni >= len(n)-1:
        result = first
        end_flag = True
    else:
        end_flag = False


    while not end_flag:
        d_val = len(ds)
        last_d = ds[d_val-1]     #Get last D elements
        current_d = {}
        reach_nodes = []
        for d in last_d.values():
            if d.mi < len(m)-1:   #Below
                tmp = Node(d.mi+1,d.ni,d_val,d,d,'b')
                tmp = snake(m,n,comp,tmp)
                if not (tmp.mi,tmp.ni) in dict_map:
                    dict_map[(tmp.mi,tmp.ni)] = True
                if not (tmp.mi,tmp.ni) in current_d:
                    current_d[(tmp.mi,tmp.ni)] = tmp
                if tmp.mi >= len(m)-1 and tmp.ni >= len(n)-1:
                    result = tmp
                    reach_nodes.append(result)
                    end_flag = True

            if d.ni < len(n)-1:   #Right
                tmp = Node(d.mi,d.ni+1,d_val,d,d,'r')
                tmp = snake(m,n,comp,tmp)
                if not (tmp.mi,tmp.ni) in dict_map:
                    dict_map[(tmp.mi,tmp.ni)] = True
                if not (tmp.mi,tmp.ni) in current_d:
                    current_d[(tmp.mi,tmp.ni)] = tmp
                if tmp.mi >= len(m)-1 and tmp.ni >= len(n)-1:
                    result = tmp
                    reach_nodes.append(result)
                    end_flag = True
        
        #if multi result, pick the most concentrated matching result.
        if end_flag:
            most_concentrated_matching = (reach_nodes[0],0)    #(node,concentrated_weight)
            if len(reach_nodes) > 1:
                for reach in reach_nodes:
                    node = reach
                    match_islands = []
                    match_start = False
                    match_count = 0
                    while node.parent != None:
                        if node.dir == 's':
                            if match_start:
                                match_count += 1
                            else:
                                match_count = 0
                                match_start = True
                        else:
                            match_islands.append(match_count)
                            match_count = 0
                            match_start = False
                        node = node.parent
                    if match_start:
                        match_islands.append(match_count)
                    if len(match_islands) == 0:
                        most_concentrated_matching = (reach,0)
                        break
                    concentrated_weight = 0
                    for island in match_islands:
                        concentrated_weight += island
                    concentrated_weight /= len(match_islands)
                    if most_concentrated_matching[1] < concentrated_weight:
                        most_concentrated_matching = (reach,concentrated_weight)
            result = most_concentrated_matching[0]
                
        ds.append(current_d)


    result_list = []
    mc_count = 0
    rm_count = 0
    ad_count = 0

    #Convert inverted list
    while True:
        result_list.append(result)
        result = result.parent
        if result.parent == None:
            break
    result_list.reverse()


    return result_func(result_list,m,n)
   





def default_print_result(result_list,m,n):
    i = 0
    mc_count = 0
    ad_count = 0
    rm_count = 0
    while i < len(result_list):
        if result_list[i].dir == 's':
            print (COL['CLEAR'] + "  " + str(n[result_list[i].ni]))
            mc_count += 1
        elif result_list[i].dir == 'r':
            print (COL['GREEN'] + "+ " + str(n[result_list[i].ni]))
            ad_count += 1
        elif result_list[i].dir == 'b':
            print (COL['RED'] + "- " + str(m[result_list[i].mi]))
            rm_count += 1
        i += 1
    print (COL['CLEAR'])
    print ('summary: match='+str(mc_count)+', add='+str(ad_count)+', remove='+str(rm_count))
    return 0


def default_compare(a,b):
    if a == b:
        return True
    return False


if __name__ == "__main__":
    argv = sys.argv
    if len(argv) >= 3:
        str1 = argv[1]
        str2 = argv[2]

        diff(str1,str2,default_compare,default_print_result)

