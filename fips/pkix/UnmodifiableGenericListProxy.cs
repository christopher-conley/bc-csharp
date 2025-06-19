using System;
using System.Collections;
using System.Collections.Generic;

namespace Org.BouncyCastle.Pkix
{


    internal abstract class UnmodifiableList<T>
        : IList<T>
    {
        public virtual IEnumerator<T> GetEnumerator()
        {
            throw new NotImplementedException();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        public void Add(T item)
        {
            throw new NotSupportedException();
        }

        public void Clear()
        {
            throw new NotSupportedException();
        }

        public abstract bool Contains(T item);


        public abstract void CopyTo(T[] array, int arrayIndex);


        public bool Remove(T item)
        {
            throw new NotSupportedException();
        }

        public abstract int Count { get; }

        public abstract T GetValue(int index);

        public bool IsReadOnly
        {
            get { return true; }
        }

        T IList<T>.this[int index]
        {
            get
            {
                return GetValue(index);
            }

            set
            {
                throw new NotImplementedException();
            }
        }

        public abstract int IndexOf(T item);


        public void Insert(int index, T item)
        {
            throw new NotSupportedException();
        }

        public void RemoveAt(int index)
        {
            throw new NotSupportedException();
        }
    }

    internal class UnmodifiableListProxy<T> : UnmodifiableList<T>
    {
        private readonly IList<T> proxiedList;

        public UnmodifiableListProxy(IList<T> list)
        {
            proxiedList = list;
        }

        public override bool Contains(T item)
        {
            return proxiedList.Contains(item);
        }

        public override void CopyTo(T[] array, int arrayIndex)
        {
            proxiedList.CopyTo(array, arrayIndex);
        }

        public override int Count
        {
            get { return proxiedList.Count; }
        }

        public override T GetValue(int index)
        {
            return proxiedList[index];
        }

        public override int IndexOf(T item)
        {
            return proxiedList.IndexOf(item);
        }

        public override IEnumerator<T> GetEnumerator()
        {
            return proxiedList.GetEnumerator();
        }
    }
}