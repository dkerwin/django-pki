"""Graphviz support for django-pki"""

try:
    import pygraphviz as pgv
except ImportError:
    raise Exception( "Failed to import pygraphviz. Disable PKI_ENABLE_GRAPHVIZ or install pygraphviz" )


def DepencyGraph(object, target):
    """Collect all objects in the depency tree and write Graphviz PNG"""
    
    ca_list = [ { 'name': object.name, 'state': object.active, 'fill': 'blue' }, ]
    
    G = pgv.AGraph(directed=True, layout="dot", pad=0.2)
    
    ## Find possible parents
    if object.parent != None:
        p = object.parent
        
        while p != None:
            ca_list.append( { 'name': p.name, 'state': p.active, } )
            p = p.parent
    
    ca_list.reverse()
    
    ## Add nodes
    for i in range(0, len(ca_list)):
        
        c = 'black'
        if ca_list[i]['state'] is False:
            c = 'red'
        
        if i > 0:
            G.add_node("dummy_start_%s" % ca_list[i]['name'], shape="folder", color="%s" % c, label="...")
            G.add_node("zummy_end_%s" % ca_list[i]['name'], shape="folder", color="%s" % c, label="...")
        
        if 'fill' in ca_list[i]:
            G.add_node(ca_list[i]['name'], shape="folder", color="%s" % c, style="filled,bold", fillcolor=ca_list[i]['fill'], fontcolor="white")
        else:
            G.add_node(ca_list[i]['name'], shape="folder", color="%s" % c)
        
    ## Draw edges
    color = "black"
    fail_from_here = False
    
    for i in range(0, len(ca_list)-1):
        if not fail_from_here:
            if ca_list[i+1]['state'] is False:
                fail_from_here = True
        else:
            color = "red"
        
        G.add_edge(ca_list[i]['name'], "dummy_start_%s" % ca_list[i+1]['name'], color="%s" % color, weight=4.5)
        G.add_edge(ca_list[i]['name'], ca_list[i+1]['name'], color="%s" % color, weight=5)
        G.add_edge(ca_list[i]['name'], "zummy_end_%s" % ca_list[i+1]['name'], color="%s" % color, weight=4.5)
    
    G.layout()
    G.draw(target, format='png')
    
    print ca_list