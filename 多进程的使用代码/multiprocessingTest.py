

import  datetime
from multiprocessing import  Process,Pool,Lock,Manager
import os
import time

#对单个文件写入，如果多进程同时操作，写入会混乱
def test(num):
    start_time = datetime.datetime.now()
    # print(start_time)
    print('Run task %s (%s)...' % (num, os.getpid()))

    for i in range(num,num+20000):
        with open('test.txt','a+',encoding='utf-8') as f:
            f.write("写入{}\n".format(i))
            # print("完成",i)
    end_time = datetime.datetime.now()
    complete_time = end_time -  start_time
    print("任务完成时间",complete_time)

#对于不同文件测试，相当于不同磁盘，效果多进程执行写入不影响
def test1(num):
    start_time = datetime.datetime.now()
    # print(start_time)
    print('Run task %s (%s)...' % (num, os.getpid()))
    # for i in range(0,num):

    # time.sleep(2)
    for i in range(num,num+20000):
        with open('test{}.txt'.format(num),'a+',encoding='utf-8') as f:
            f.write("写入{}\n".format(i))
            # print("完成",i)
    end_time = datetime.datetime.now()
    complete_time = end_time -  start_time
    print("任务完成时间",complete_time)

#进程锁
def test2(num,lock):
    lock.acquire()
    start_time = datetime.datetime.now()
    # print(start_time)
    print('Run task %s (%s)...' % (num, os.getpid()))
    # for i in range(0,num):

    # time.sleep(2)

    for i in range(num,num+20000):

        with open('test.txt','a+',encoding='utf-8') as f:
            f.write("写入{}\n".format(i))
            # print("完成",i)

    end_time = datetime.datetime.now()
    complete_time = end_time -  start_time
    print("任务完成时间",complete_time)
    lock.release()


def testCallBack(num):
    start_time = datetime.datetime.now()
    time.sleep(1)
    # q=[]
    # for i in num:
    #     q.append(i)
    end_time = datetime.datetime.now()
    complete_time = end_time -  start_time
    print("任务完成时间",complete_time)
    return num


def callBack(x):


    for i in range(x-20000,x):
        with open('./callbackTest.txt','a+',encoding='utf-8') as f:
            f.write("写入{}\n".format(i))


if __name__ == '__main__':


    # 单进程
    # test(100000)
    # test(20000)  #3s


    '''
    多进程：
    多进程不同文件正常执行，同个文件能写入，但是执行会异常
    '''

    # 启动多个子进程
    '''
    定义多个process 不同函数
    '''
    # print('父进程 %s.' % os.getpid())
    #
    # p1 = Process(target=test,args=(3,))
    # p2 = Process(target=test1,args=(3,))
    # print('Child process will start.')
    # p1.start()
    # p2.start()
    # p1.join()
    # p2.join()
    # print('父进程 %s.' % os.getpid())


    # 进程池
    # print('Parent process %s.' % os.getpid())
    # p = Pool(5)
    # for i in range(0,100000,20000):
    #     # print(i)
    #     p.apply_async(test, args=(i,))
    #     # p.apply(test, args=(i,)) #同步写入
    #
    # print('Waiting for all subprocesses done...')
    # p.close()
    # p.join()
    # print('All subprocesses done.')

    #多进程锁 lock()不能用于pool
    # lock = Manager().Lock()  #仅用于进程池锁
    # print('Parent process %s.' % os.getpid())
    # p = Pool(5)
    # for i in range(0,100000,20000):
    #     # print(i)
    #     p.apply_async(test2, args=(i,lock,))
    #
    # print('Waiting for all subprocesses done...')
    # p.close()
    # p.join()
    # print('All subprocesses done.')
    '''
    if __name__ == '__main__':
    # lock= Lock()
    for i in range(3):
        p=Process(target=work,args=(lock,))
        p.start()
    #非连接池的方式只允许使用lock= Lock() 上锁，用manager 会报错
    '''

    #测试进程池回调
    print('Parent process %s.' % os.getpid())
    p = Pool(5)
    for i in range(20000,120000,20000):
        print(i)
        p.apply_async(testCallBack, args=(i,),callback=callBack)
        # p.apply(test, args=(i,)) #同步写入

    print('Waiting for all subprocesses done...')
    p.close()
    p.join()
    print('All subprocesses done.')
