from ex2 import invmod,CongEquations

#print(invmod(7,18))
#print(invmod(13,15))

#print(5*13%18)

ce=CongEquations([1,2,4],[2,9,5])
print(ce.solve_CRT())